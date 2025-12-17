#include "source/server/admin/cpu_info_handler.h"

#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>

#if defined(__linux__)
#include <dirent.h>
#include <unistd.h>
#include <cstring>

#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#endif

#include "source/common/common/fmt.h"
#include "source/common/http/headers.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"
#include "source/server/admin/cpu_info_params.h"

namespace Envoy {
namespace Server {

#if defined(__linux__)

// Envoy thread naming conventions (Linux /proc/<pid>/task/<tid>/stat comm field).
static constexpr absl::string_view kWorkerThreadPrefix = "wrk:worker_";
static constexpr absl::string_view kMainThreadName = "envoy";

// Adapted from procps-ng's cpuCount().
// See: https://gitlab.com/procps-ng/procps/-/blob/master/library/stat.c
long CpuInfoHandler::cpuCount() {
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  if (cpus < 1) {
    return 1;
  }
  return cpus;
}

bool CpuInfoHandler::readTotalCpuJiffies(unsigned long long& total_jiffies) {
  std::ifstream stat_file("/proc/stat");
  if (!stat_file.is_open()) {
    return false;
  }

  std::string line;
  std::getline(stat_file, line);
  if (!absl::StartsWith(line, "cpu ")) {
    return false;
  }

  // Parse: "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
  // Sum all fields to get total jiffies across all CPUs.
  std::istringstream iss(line.substr(5)); // skip "cpu  "
  unsigned long long sum = 0;
  unsigned long long value;
  while (iss >> value) {
    sum += value;
  }

  total_jiffies = sum;
  return true;
}

// Adapted from procps-ng's stat2proc().
// See: https://gitlab.com/procps-ng/procps/-/blob/master/library/readproc.c
// Parses /proc/*/stat files, handling process names that contain special characters.
bool CpuInfoHandler::stat2proc(const char* stat_line, proc_t& P) {
  P = {};

  // Find the opening '(' of the command name
  const char* S = strchr(stat_line, '(');
  if (!S) {
    return false;
  }
  S++; // skip '('

  // Find the closing ')' of the command name (search from the end to handle names with ')')
  const char* tmp = strrchr(S, ')');
  if (!tmp || !tmp[1]) {
    return false;
  }

  // Extract comm (field 2, inside parentheses)
  P.comm.assign(S, tmp - S);

  // Parse the rest of the fields after ") "
  S = tmp + 2;

  // Use a compact sscanf to pick out only the fields we need.
  //
  // /proc/<pid>/stat fields (proc(5)):
  //   3  state
  //   4  ppid
  //   5  pgrp
  //   6  session
  //   7  tty_nr
  //   8  tpgid
  //   9  flags
  //  10  minflt
  //  11  cminflt
  //  12  majflt
  //  13  cmajflt
  //  14  utime
  //  15  stime
  //  16  cutime
  //  17  cstime
  //  18  priority
  //  19  nice
  //  20  num_threads
  //  21  itrealvalue
  //  22  starttime
  const int ret = std::sscanf(
      S,
      "%*c "                      // state
      "%*d %*d %*d %*d %*d "      // ppid, pgrp, session, tty_nr, tpgid
      "%*lu %*lu %*lu %*lu %*lu " // flags, minflt, cminflt, majflt, cmajflt
      "%llu %llu %llu %llu "      // utime, stime, cutime, cstime
      "%*ld %*ld %*ld "           // priority, nice, num_threads
      "%*lu "                     // itrealvalue
      "%llu",                     // starttime
      &P.utime, &P.stime, &P.cutime, &P.cstime, &P.start_time);

  return ret == 5 && P.start_time > 0;
}

EnvoyThreadCpuStatSamples CpuInfoHandler::readEnvoyThreadSamples(pid_t pid, uint32_t concurrency) {
  EnvoyThreadCpuStatSamples samples;

  const std::string task_dir = fmt::format("/proc/{}/task", pid);
  DIR* dir = opendir(task_dir.c_str());
  if (dir == nullptr) {
    return samples;
  }

  while (dirent* entry = readdir(dir)) {
    // Skip "." and "..".
    if (entry->d_name[0] == '.' &&
        (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
      continue;
    }

    char* endptr = nullptr;
    const long tid_long = std::strtol(entry->d_name, &endptr, 10);
    if (endptr == nullptr || *endptr != '\0' || tid_long <= 0) {
      continue;
    }
    const pid_t tid = static_cast<pid_t>(tid_long);

    const std::string stat_path = fmt::format("/proc/{}/task/{}/stat", pid, tid);
    std::ifstream stat_file(stat_path);
    if (!stat_file.is_open()) {
      continue;
    }

    std::string stat_line;
    std::getline(stat_file, stat_line);
    if (stat_line.empty()) {
      continue;
    }

    proc_t P;
    if (!stat2proc(stat_line.c_str(), P)) {
      continue;
    }

    // Only process worker threads + main thread.
    const absl::string_view comm(P.comm);
    const bool is_worker = absl::StartsWith(comm, kWorkerThreadPrefix);
    const bool is_main = (comm == kMainThreadName);
    if (!is_worker && !is_main) {
      continue;
    }

    if (is_worker) {
      // Parse the worker index from the thread name.
      uint32_t worker_index = 0;
      const absl::string_view index_str = comm.substr(kWorkerThreadPrefix.size());
      if (!absl::SimpleAtoi(index_str, &worker_index) || worker_index >= concurrency) {
        continue;
      }

      samples.workers[worker_index] = ThreadSample{P.utime, P.stime};
    } else {
      samples.main = ThreadSample{P.utime, P.stime};
      samples.has_main = true;
    }
  }

  closedir(dir);
  return samples;
}

Http::Code CpuInfoHandler::measureDeltaCpuUtilization(uint64_t sampling_interval_ms,
                                                      CpuInfoFormat format,
                                                      Http::ResponseHeaderMap& response_headers,
                                                      Buffer::Instance& response) {
  const pid_t pid = getpid();
  const uint32_t concurrency = server_.options().concurrency();
  const long num_cpus = cpuCount();
  const uint64_t sampling_interval_us = sampling_interval_ms * 1000;

  // Take first sample: total CPU jiffies and per-thread stats
  unsigned long long prev_total_jiffies = 0;
  if (!readTotalCpuJiffies(prev_total_jiffies)) {
    return returnError("Failed to read /proc/stat.", format, response_headers, response);
  }
  EnvoyThreadCpuStatSamples prev_samples = readEnvoyThreadSamples(pid, concurrency);

  // Sleep for the sampling interval
  usleep(sampling_interval_us);

  // Take second sample: total CPU jiffies and per-thread stats
  unsigned long long cur_total_jiffies = 0;
  if (!readTotalCpuJiffies(cur_total_jiffies)) {
    return returnError("Failed to read /proc/stat.", format, response_headers, response);
  }
  EnvoyThreadCpuStatSamples cur_samples = readEnvoyThreadSamples(pid, concurrency);

  // Calculate total jiffies per CPU over the sampling interval.
  const unsigned long long delta_total = cur_total_jiffies - prev_total_jiffies;
  if (delta_total == 0) {
    return returnError("No CPU time elapsed.", format, response_headers, response);
  }
  const double total_jiffies_per_cpu = static_cast<double>(delta_total) / static_cast<double>(num_cpus);

  // Calculate per-worker CPU percentage
  std::vector<double> cpu_per_worker(concurrency, 0.0);
  std::vector<bool> worker_has_sample(concurrency, false);
  bool has_main_thread_sample = false;
  double main_thread_cpu = 0.0;

  for (uint32_t i = 0; i < concurrency; ++i) {
    auto prev_it = prev_samples.workers.find(i);
    auto cur_it = cur_samples.workers.find(i);

    if (prev_it != prev_samples.workers.end() && cur_it != cur_samples.workers.end()) {
      const ThreadSample& prev = prev_it->second;
      const ThreadSample& cur = cur_it->second;

      // Calculate delta_task = (cur->utime + cur->stime) - (prev->utime + prev->stime)
      const unsigned long long prev_task = prev.utime + prev.stime;
      const unsigned long long cur_task = cur.utime + cur.stime;
      const unsigned long long delta_task = cur_task - prev_task;

      // Irix-style per-thread %CPU, like top's default, using per-CPU total jiffies
      // over the interval as the time base. Round to 2 decimal places.
      const double thread_pcpu =
          std::round((static_cast<double>(delta_task) / total_jiffies_per_cpu) * 10000.0) / 100.0;

      cpu_per_worker[i] = thread_pcpu;
      worker_has_sample[i] = true;
    }
  }

  // Optional main thread CPU.
  if (prev_samples.has_main && cur_samples.has_main) {
    const ThreadSample& prev = prev_samples.main;
    const ThreadSample& cur = cur_samples.main;
    const unsigned long long prev_task = prev.utime + prev.stime;
    const unsigned long long cur_task = cur.utime + cur.stime;
    const unsigned long long delta_task = cur_task - prev_task;
    main_thread_cpu =
        std::round((static_cast<double>(delta_task) / total_jiffies_per_cpu) * 10000.0) / 100.0;
    has_main_thread_sample = true;
  }

  // Format output
  if (format == CpuInfoFormat::Text) {
    response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Text);
    for (uint32_t i = 0; i < concurrency; ++i) {
      const std::string name = fmt::format("{}{}", kWorkerThreadPrefix, i);
      if (worker_has_sample[i]) {
        response.add(fmt::format("{}: {:.2f}%\n", name, cpu_per_worker[i]));
      } else {
        response.add(fmt::format("{}: n/a\n", name));
      }
    }
    if (has_main_thread_sample) {
      response.add(fmt::format("{}: {:.2f}%\n", kMainThreadName, main_thread_cpu));
    } else {
      response.add(fmt::format("{}: n/a\n", kMainThreadName));
    }
    return Http::Code::OK;
  }

  response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Json);

  // Build JSON output: {"wrk:worker_0": 12.34, "wrk:worker_1": null, "envoy": 5.67}
  Protobuf::Struct root;
  auto& fields = *root.mutable_fields();

  for (uint32_t i = 0; i < concurrency; ++i) {
    const std::string name = fmt::format("{}{}", kWorkerThreadPrefix, i);
    if (worker_has_sample[i]) {
      fields[name].set_number_value(cpu_per_worker[i]);
    } else {
      fields[name].set_null_value(Protobuf::NullValue::NULL_VALUE);
    }
  }

  if (has_main_thread_sample) {
    fields[kMainThreadName].set_number_value(main_thread_cpu);
  } else {
    fields[kMainThreadName].set_null_value(Protobuf::NullValue::NULL_VALUE);
  }

  response.add(MessageUtil::getJsonStringFromMessageOrError(root, true, true));
  return Http::Code::OK;
}

#endif

Http::Code CpuInfoHandler::returnError(absl::string_view msg, CpuInfoFormat format,
                                       Http::ResponseHeaderMap& response_headers,
                                       Buffer::Instance& response) {
  if (format == CpuInfoFormat::Json) {
    response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Json);
    Protobuf::Struct err;
    (*err.mutable_fields())["error"].set_string_value(std::string(msg));
    response.add(MessageUtil::getJsonStringFromMessageOrError(err, true, true));
  } else {
    response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Text);
    response.add(std::string(msg));
    response.add("\n");
  }
  return Http::Code::OK;
}

CpuInfoHandler::CpuInfoHandler(Server::Instance& server) : HandlerContextBase(server) {}

Http::Code CpuInfoHandler::handlerWorkersCpu(Http::ResponseHeaderMap& response_headers,
                                             Buffer::Instance& response, AdminStream& admin_stream) {
  CpuInfoParams params;
  Buffer::OwnedImpl parse_error;
  const Http::Code parse_code =
      params.parse(admin_stream.getRequestHeaders().getPathValue(), parse_error);
  if (parse_code != Http::Code::OK) {
    response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Text);
    response.move(parse_error);
    return parse_code;
  }

#if defined(__linux__)
  return measureDeltaCpuUtilization(params.sampling_interval_ms_, params.format_, response_headers,
                                    response);
#else
  return returnError("Worker CPU utilization is only supported on Linux.", params.format_,
                     response_headers, response);
#endif
}

} // namespace Server
} // namespace Envoy


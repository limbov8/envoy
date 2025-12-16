#include "source/server/admin/cpu_info_handler.h"

#include <fstream>
#include <sstream>

#if defined(__linux__)
#include <dirent.h>
#include <unistd.h>

#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#endif

#include "source/common/common/fmt.h"

namespace Envoy {
namespace Server {

#if defined(__linux__)
// Read the system uptime in seconds from /proc/uptime.
static bool readSystemUptime(double& uptime_seconds) {
  std::ifstream uptime_file("/proc/uptime");
  if (!uptime_file.is_open()) {
    return false;
  }
  uptime_file >> uptime_seconds;
  return uptime_file.good();
}
#endif

CpuInfoHandler::CpuInfoHandler(Server::Instance& server) : HandlerContextBase(server) {}

Http::Code CpuInfoHandler::handlerWorkersCpu(Http::ResponseHeaderMap&, Buffer::Instance& response,
                                             AdminStream&) {
#if defined(__linux__)
  const pid_t pid = getpid();
  const long ticks_per_second = sysconf(_SC_CLK_TCK);
  const int num_cpus = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
  const uint32_t concurrency = server_.options().concurrency();

  double uptime_seconds = 0;
  if (!readSystemUptime(uptime_seconds) || ticks_per_second <= 0 || num_cpus <= 0 ||
      concurrency == 0) {
    response.add("Worker CPU utilization is not available on this platform.\n");
    return Http::Code::OK;
  }

  // Pre-size containers for per-worker CPU.
  std::vector<double> cpu_per_worker(concurrency, 0.0);
  std::vector<bool> worker_has_sample(concurrency, false);

  const std::string task_dir = fmt::format("/proc/{}/task", pid);
  DIR* dir = opendir(task_dir.c_str());
  if (dir == nullptr) {
    response.add("Worker CPU utilization is not available on this platform.\n");
    return Http::Code::OK;
  }

  // Traverse all threads in this process: each entry name in /proc/<pid>/task is a TID.
  while (dirent* entry = readdir(dir)) {
    // Skip "." and "..".
    if (entry->d_name[0] == '.' &&
        (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
      continue;
    }

    char* endptr = nullptr;
    const long tid_long = std::strtol(entry->d_name, &endptr, 10);
    if (endptr == nullptr || *endptr != '\0' || tid_long <= 0) {
      continue; // Not a numeric thread id.
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

    // Extract the thread name from the (comm) field and the remainder of the stat line.
    const auto lparen = stat_line.find('(');
    const auto rparen = stat_line.rfind(')');
    if (lparen == std::string::npos || rparen == std::string::npos || rparen <= lparen) {
      continue;
    }

    const std::string comm = stat_line.substr(lparen + 1, rparen - lparen - 1);

    // Worker threads are named "wrk:<dispatcher_name>", where dispatcher_name is "worker_<i>".
    // That yields names like "wrk:worker_0", one per Envoy worker.
    static constexpr absl::string_view kWorkerPrefix = "wrk:worker_";
    if (!absl::StartsWith(comm, kWorkerPrefix)) {
      continue;
    }

    // Parse the worker index from the suffix of the name.
    const absl::string_view index_str = absl::string_view(comm).substr(kWorkerPrefix.size());
    uint32_t worker_index = 0;
    if (!absl::SimpleAtoi(index_str, &worker_index) || worker_index >= concurrency) {
      continue;
    }

    // Parse the timing fields from the remainder of the stat line (fields 3+).
    const std::string rest = stat_line.substr(rparen + 2);
    std::istringstream iss(rest);

    double utime_ticks = 0;
    double stime_ticks = 0;
    long long starttime_ticks = 0;

    std::string token;
    int index = 1;
    while (iss >> token) {
      if (index == 11) {
        utime_ticks = std::strtod(token.c_str(), nullptr);
      } else if (index == 12) {
        stime_ticks = std::strtod(token.c_str(), nullptr);
      } else if (index == 19) {
        starttime_ticks = std::strtoll(token.c_str(), nullptr, 10);
        break;
      }
      ++index;
    }

    if (starttime_ticks <= 0) {
      continue;
    }

    const double total_time_seconds =
        (utime_ticks + stime_ticks) / static_cast<double>(ticks_per_second);
    const double starttime_seconds =
        static_cast<double>(starttime_ticks) / static_cast<double>(ticks_per_second);
    const double seconds = uptime_seconds - starttime_seconds;

    if (seconds <= 0.0) {
      continue;
    }

    const double cpu_percent =
        (total_time_seconds / seconds) * (100.0 / static_cast<double>(num_cpus));
    cpu_per_worker[worker_index] = cpu_percent;
    worker_has_sample[worker_index] = true;
  }

  closedir(dir);

  response.add("Each worker thread CPU utilization (similar to Linux top):\n");
  for (uint32_t i = 0; i < concurrency; ++i) {
    if (worker_has_sample[i]) {
      response.add(
          fmt::format("Worker {}: {:.2f}%\n", i, cpu_per_worker[i]));
    } else {
      response.add(fmt::format("Worker {}: n/a\n", i));
    }
  }
#else
  response.add("Worker CPU utilization is only supported on Linux.\n");
#endif

  return Http::Code::OK;
}

} // namespace Server
} // namespace Envoy


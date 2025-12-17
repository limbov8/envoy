#include "source/server/admin/cpu_info_handler.h"

#include <fstream>
#include <sstream>

#if defined(__linux__)
#include <dirent.h>
#include <unistd.h>
#include <cstring>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#endif

#include "source/common/common/fmt.h"

namespace Envoy {
namespace Server {

#if defined(__linux__)

// Sampling delay in microseconds, matching top.c's LIB_USLEEP
constexpr int LIB_USLEEP = 200000; // 200ms

// Equivalent to procps-ng's procps_cpu_count(): obtain number of online CPUs
// with a safe minimum of 1.
static long procps_cpu_count() {
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  if (cpus < 1) {
    return 1;
  }
  return cpus;
}

// Process information structure matching procps implementation.
// Keeps all fields even if not currently used for future extensibility.
struct proc_t {
  int pid;                    // process id
  char state;                 // state (R, S, D, Z, T, etc.)
  int ppid;                   // parent process id
  int pgrp;                   // process group id
  int session;                // session id
  int tty;                    // controlling tty (tty_nr)
  int tpgid;                  // tty process group id
  unsigned long flags;        // kernel flags
  unsigned long min_flt;      // minor page faults
  unsigned long cmin_flt;     // minor page faults of children
  unsigned long maj_flt;      // major page faults
  unsigned long cmaj_flt;     // major page faults of children
  unsigned long long utime;   // user-mode CPU time accumulated by process
  unsigned long long stime;   // kernel-mode CPU time accumulated by process
  unsigned long long cutime;  // cumulative utime of process and reaped children
  unsigned long long cstime;  // cumulative stime of process and reaped children
  int priority;               // kernel scheduling priority
  int nice;                   // nice value
  int nlwp;                   // number of threads
  unsigned long alarm;        // 'alarm' == it_real_value (obsolete, always 0)
  unsigned long long start_time; // start time of process -- seconds since system boot
  unsigned long vsize;        // virtual memory size in bytes
  unsigned long rss;          // resident set size
  unsigned long rss_rlim;     // rss limit
  unsigned long start_code;   // address of start of code segment
  unsigned long end_code;     // address of end of code segment
  unsigned long start_stack;  // address of start of stack
  unsigned long kstk_esp;     // kernel stack pointer
  unsigned long kstk_eip;     // kernel instruction pointer
  unsigned long wchan;        // wait channel
  int exit_signal;            // signal to send to parent on exit
  int processor;              // CPU number last executed on
  int rtprio;                 // real-time priority
  int sched;                  // scheduling policy
  unsigned long long blkio_tics; // time spent waiting for block IO
  unsigned long long gtime;   // guest time (time spent in guest mode)
  unsigned long long cgtime;  // guest time of children
  char comm[64];              // command name (from within parentheses)
};

// procps-ng/procps/library/readproc.c stat2proc
// Reads /proc/*/stat files, being careful not to trip over processes with
// names like ":-) 1 2 3 4 5 6".
// Returns true on success, false on failure.
static bool stat2proc(const char* stat_line, proc_t& P) {
  // Initialize default values for optional/newer kernel fields
  P.processor = 0;
  P.rtprio = -1;
  P.sched = -1;
  P.nlwp = 0;
  P.comm[0] = '\0';

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

  // Extract command name
  size_t comm_len = tmp - S;
  if (comm_len >= sizeof(P.comm)) {
    comm_len = sizeof(P.comm) - 1;
  }
  memcpy(P.comm, S, comm_len);
  P.comm[comm_len] = '\0';

  // Parse the rest of the fields after ") "
  S = tmp + 2;

  int ret = sscanf(S,
                   "%c "                      // state
                   "%d %d %d %d %d "          // ppid, pgrp, sid, tty_nr, tty_pgrp
                   "%lu %lu %lu %lu %lu "     // flags, min_flt, cmin_flt, maj_flt, cmaj_flt
                   "%llu %llu %llu %llu "     // utime, stime, cutime, cstime
                   "%d %d "                   // priority, nice
                   "%d "                      // num_threads
                   "%lu "                     // 'alarm' == it_real_value (obsolete, always 0)
                   "%llu "                    // start_time
                   "%lu "                     // vsize
                   "%lu "                     // rss
                   "%lu %lu %lu %lu %lu %lu " // rsslim, start_code, end_code, start_stack, esp, eip
                   "%*s %*s %*s %*s "         // pending, blocked, sigign, sigcatch <=== DISCARDED
                   "%lu %*u %*u "             // 0 (former wchan), 0, 0 <=== Placeholders only
                   "%d %d "                   // exit_signal, task_cpu
                   "%d %d "                   // rt_priority, policy (sched)
                   "%llu %llu %llu",          // blkio_ticks, gtime, cgtime
                   &P.state,
                   &P.ppid, &P.pgrp, &P.session, &P.tty, &P.tpgid,
                   &P.flags, &P.min_flt, &P.cmin_flt, &P.maj_flt, &P.cmaj_flt,
                   &P.utime, &P.stime, &P.cutime, &P.cstime,
                   &P.priority, &P.nice,
                   &P.nlwp,
                   &P.alarm,
                   &P.start_time,
                   &P.vsize,
                   &P.rss,
                   &P.rss_rlim, &P.start_code, &P.end_code, &P.start_stack, &P.kstk_esp,
                   &P.kstk_eip,
                   /*     P.signal, P.blocked, P.sigignore, P.sigcatch,   */ /* can't use */
                   &P.wchan, /* &P.nswap, &P.cnswap, */ /* nswap and cnswap dead for 2.4.xx and up */
                   /* -- Linux 2.0.35 ends here -- */
                   &P.exit_signal, &P.processor, /* 2.2.1 ends with "exit_signal" */
                   /* -- Linux 2.2.8 to 2.5.17 end here -- */
                   &P.rtprio, &P.sched, /* both added to 2.5.18 */
                   &P.blkio_tics, &P.gtime, &P.cgtime);

  if (!P.nlwp) {
    P.nlwp = 1;
  }

  // Expect at least the core fields to be parsed (up to and including start_time)
  return ret >= 20;
}

// Read total CPU jiffies from /proc/stat (sum of all CPU time fields).
// This matches what top.c does to calculate system-wide CPU usage.
static bool readTotalCpuJiffies(unsigned long long& total_jiffies) {
  std::ifstream stat_file("/proc/stat");
  if (!stat_file.is_open()) {
    return false;
  }

  std::string line;
  std::getline(stat_file, line);
  if (!absl::StartsWith(line, "cpu ")) {
    return false;
  }

  // The first line is "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
  // We sum all fields to get total jiffies.
  std::istringstream iss(line.substr(5)); // skip "cpu  "
  unsigned long long sum = 0;
  unsigned long long value;
  while (iss >> value) {
    sum += value;
  }

  total_jiffies = sum;
  return true;
}


// Sample data for a worker thread
struct WorkerSample {
  pid_t tid;
  uint32_t worker_index;
  unsigned long long utime;
  unsigned long long stime;
  bool valid;
};

// Read all worker thread stats for a single sample.
// Returns a map of worker_index -> WorkerSample.
static absl::flat_hash_map<uint32_t, WorkerSample>
readWorkerThreadStats(pid_t pid, uint32_t concurrency) {
  absl::flat_hash_map<uint32_t, WorkerSample> samples;

  const std::string task_dir = fmt::format("/proc/{}/task", pid);
  DIR* dir = opendir(task_dir.c_str());
  if (dir == nullptr) {
    return samples;
  }

  static constexpr absl::string_view kWorkerPrefix = "wrk:worker_";

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

    // Only process worker threads
    if (!absl::StartsWith(P.comm, kWorkerPrefix)) {
      continue;
    }

    // Parse the worker index from the thread name
    const absl::string_view index_str = absl::string_view(P.comm).substr(kWorkerPrefix.size());
    uint32_t worker_index = 0;
    if (!absl::SimpleAtoi(index_str, &worker_index) || worker_index >= concurrency) {
      continue;
    }

    WorkerSample sample;
    sample.tid = tid;
    sample.worker_index = worker_index;
    sample.utime = P.utime;
    sample.stime = P.stime;
    sample.valid = true;
    samples[worker_index] = sample;
  }

  closedir(dir);
  return samples;
}

#endif

CpuInfoHandler::CpuInfoHandler(Server::Instance& server) : HandlerContextBase(server) {}

Http::Code CpuInfoHandler::handlerWorkersCpu(Http::ResponseHeaderMap&, Buffer::Instance& response,
                                             AdminStream&) {
#if defined(__linux__)
  const pid_t pid = getpid();
  const uint32_t concurrency = server_.options().concurrency();
  const int num_cpus = static_cast<int>(procps_cpu_count());

  if (concurrency == 0) {
    response.add("Worker CPU utilization is not available (concurrency is 0).\n");
    return Http::Code::OK;
  }

  // Take first sample: total CPU jiffies and per-thread stats
  unsigned long long prev_total_jiffies = 0;
  if (!readTotalCpuJiffies(prev_total_jiffies)) {
    response.add("Failed to read total CPU jiffies.\n");
    return Http::Code::OK;
  }

  absl::flat_hash_map<uint32_t, WorkerSample> prev_samples =
      readWorkerThreadStats(pid, concurrency);

  // Sleep for the sampling interval
  // do an extra procs refresh to avoid %cpu distortions...
  usleep(LIB_USLEEP);

  // Take second sample: total CPU jiffies and per-thread stats
  unsigned long long cur_total_jiffies = 0;
  if (!readTotalCpuJiffies(cur_total_jiffies)) {
    response.add("Failed to read total CPU jiffies on second sample.\n");
    return Http::Code::OK;
  }

  absl::flat_hash_map<uint32_t, WorkerSample> cur_samples =
      readWorkerThreadStats(pid, concurrency);

  // Calculate delta_total (total system CPU time across all CPUs)
  const unsigned long long delta_total = cur_total_jiffies - prev_total_jiffies;

  response.add(fmt::format("delta_total: {}\n", delta_total));
  response.add(fmt::format("prev_total_jiffies: {}\n", prev_total_jiffies));
  response.add(fmt::format("cur_total_jiffies: {}\n", cur_total_jiffies));

  if (delta_total == 0) {
    response.add("No CPU time elapsed between samples.\n");
    return Http::Code::OK;
  }

  // Per-CPU share of total jiffies over the sampling interval.
  const double total_jiffies_per_cpu =
      static_cast<double>(delta_total) / static_cast<double>(num_cpus);

  // Calculate per-worker CPU percentage
  std::vector<double> cpu_per_worker(concurrency, 0.0);
  std::vector<bool> worker_has_sample(concurrency, false);

  for (uint32_t i = 0; i < concurrency; ++i) {
    auto prev_it = prev_samples.find(i);
    auto cur_it = cur_samples.find(i);

    if (prev_it != prev_samples.end() && cur_it != cur_samples.end()) {
      const WorkerSample& prev = prev_it->second;
      const WorkerSample& cur = cur_it->second;

      response.add(fmt::format("prev.tid: {}\n", prev.tid));
      response.add(fmt::format("prev.worker_index: {}\n", prev.worker_index));
      response.add(fmt::format("prev.utime: {}\n", prev.utime));
      response.add(fmt::format("prev.stime: {}\n", prev.stime));
      response.add(fmt::format("cur.tid: {}\n", cur.tid));
      response.add(fmt::format("cur.worker_index: {}\n", cur.worker_index));
      response.add(fmt::format("cur.utime: {}\n", cur.utime));
      response.add(fmt::format("cur.stime: {}\n", cur.stime));

      // Calculate delta_task = (cur->utime + cur->stime) - (prev->utime + prev->stime)
      const unsigned long long prev_task = prev.utime + prev.stime;
      const unsigned long long cur_task = cur.utime + cur.stime;
      const unsigned long long delta_task = cur_task - prev_task;

      response.add(fmt::format("delta_task: {}\n", delta_task));

      // Irix-style per-thread %CPU, like top's default, using per-CPU total jiffies
      // over the interval as the time base.
      const double thread_pcpu =
          (static_cast<double>(delta_task) / total_jiffies_per_cpu) * 100.0;

      cpu_per_worker[i] = thread_pcpu;
      worker_has_sample[i] = true;
    }
  }

  response.add("Each worker thread CPU utilization (similar to Linux top):\n");
  for (uint32_t i = 0; i < concurrency; ++i) {
    if (worker_has_sample[i]) {
      response.add(fmt::format("Worker {}: {:.2f}%\n", i, cpu_per_worker[i]));
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


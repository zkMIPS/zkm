use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind};
pub(crate) fn print_mem_usage(stage: &str) {
    let mut sys = System::new_all();
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_cwd(UpdateKind::Always));

    let pid = std::process::id();
    let processes = sys.processes();
    let p = processes.get(&Pid::from_u32(pid as _)).unwrap();

    log::info!("{} => process: {}, {:?}", stage, pid, p.cwd().unwrap());
    // RAM and swap information:
    let unit = 1024 * 1024;
    log::info!("current process memory: {} Mbytes", p.memory() / unit);
    log::info!(
        "current process virtual memory : {} Mbytes",
        p.virtual_memory() / unit
    );

    log::info!("total memory: {} Mbytes", sys.total_memory() / unit);
    log::info!("used memory : {} Mbytes", sys.used_memory() / unit);
    log::info!("total swap  : {} Mbytes", sys.total_swap() / unit);
    log::info!("used swap   : {} Mbytes", sys.used_swap() / unit);
}

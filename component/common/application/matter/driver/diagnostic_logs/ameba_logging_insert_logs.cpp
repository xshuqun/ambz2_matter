#include <FreeRTOS.h>
#include <platform_stdlib.h>
#include <platform_opts.h>
#include <device_lock.h>
#include <flash_api.h>
#include <string>

#if defined(CONFIG_ENABLE_AMEBA_DLOG) && (CONFIG_ENABLE_AMEBA_DLOG == 1)
#include <lfs.h>
#include <matter_fs.h>
#include <diagnostic_logs/ameba_diagnosticlogs_provider_delegate_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

_WEAK void matter_insert_user_log(uint8_t* data, uint32_t data_len)
{
    int res;
    uint unused_writecount = 0;
    lfs_file_t* fp = chip::app::Clusters::DiagnosticLogs::AmebaDiagnosticLogsProvider::GetFpUserLog();
    bool fsReady = chip::app::Clusters::DiagnosticLogs::AmebaDiagnosticLogsProvider::IsFSReady();

    if (!fsReady) {
        res = matter_fs_fopen(USER_LOG_FILENAME, fp, LFS_O_RDWR | LFS_O_CREAT);
        if (res != 0)
        {
            ChipLogError(DeviceLayer, "Open res: %d", res);
            return;
        }
    }

    ChipLogProgress(DeviceLayer, "Copy User log.....");

    res = matter_fs_fwrite(fp, data, data_len, &unused_writecount); // write to FS
    if (res >= 0)
    {
        ChipLogProgress(DeviceLayer, "Wrote %d bytes to userlog", unused_writecount);
    }
    else
    {
        ChipLogError(DeviceLayer, "Write error! %d", res);
        goto exit;
    }

exit:
    if (!fsReady) {
        matter_fs_fclose(fp);
    }
    return;
}

_WEAK void matter_insert_network_log(uint8_t* data, uint32_t data_len)
{
    int res;
    uint unused_writecount = 0;
    lfs_file_t* fp = chip::app::Clusters::DiagnosticLogs::AmebaDiagnosticLogsProvider::GetFpNetdiagLog();
    bool fsReady = chip::app::Clusters::DiagnosticLogs::AmebaDiagnosticLogsProvider::IsFSReady();

    if (!fsReady) {
        res = matter_fs_fopen(NET_LOG_FILENAME, fp, LFS_O_RDWR | LFS_O_CREAT);
        if (res != 0)
        {
            ChipLogError(DeviceLayer, "Open res: %d", res);
            return;
        }
    }

    ChipLogProgress(DeviceLayer, "Copy Network log.....");

    res = matter_fs_fwrite(fp, data, data_len, &unused_writecount); // write to FS
    if (res >= 0)
    {
        ChipLogProgress(DeviceLayer, "Wrote %d bytes to Networklog", unused_writecount);
    }
    else
    {
        ChipLogError(DeviceLayer, "Write error! %d", res);
        goto exit;
    }

exit:
    if (!fsReady) {
        matter_fs_fclose(fp);
    }
    return;
}

_WEAK void matter_insert_crash_log(uint8_t* data, uint32_t data_len)
{
    int res;
    uint unused_writecount = 0;
    lfs_file_t* fp = chip::app::Clusters::DiagnosticLogs::AmebaDiagnosticLogsProvider::GetFpCrashLog();
    bool fsReady = chip::app::Clusters::DiagnosticLogs::AmebaDiagnosticLogsProvider::IsFSReady();

    if (!fsReady) {
        res = matter_fs_fopen(CRASH_LOG_FILENAME, fp, LFS_O_RDWR | LFS_O_CREAT);
        if (res != 0)
        {
            ChipLogError(DeviceLayer, "Open res: %d", res);
            return;
        }
    }

    ChipLogProgress(DeviceLayer, "Copy Crash log.....");

    res = matter_fs_fwrite(fp, data, data_len, &unused_writecount); // write to FS
    if (res >= 0)
    {
        ChipLogProgress(DeviceLayer, "Wrote %d bytes to Crashlog", unused_writecount);
    }
    else
    {
        ChipLogError(DeviceLayer, "Write error! %d", res);
        goto exit;
    }

exit:
    if (!fsReady) {
        matter_fs_fclose(fp);
    }
    return;
}

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_ENABLE_AMEBA_DLOG */

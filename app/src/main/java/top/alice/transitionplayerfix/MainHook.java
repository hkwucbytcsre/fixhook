package top.alice.transitionplayerfix;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

import top.alice.transitionplayerfix.hook.LauncherProcessHook;
import top.alice.transitionplayerfix.hook.SystemUIHook;
import top.alice.transitionplayerfix.hook.WindowOrganizerHook;

/**
 * libxposed API 102 模块入口。
 *
 * Hook 分布（三层防御）：
 *   1. system_server → WindowOrganizerHook    入口拦截
 *   2. SystemUI      → SystemUIHook           参数校验
 *   3. Launcher      → LauncherProcessHook    最终防线
 */
public class MainHook extends XposedModule {

    private static final String TAG = "TransitionPlayerFix";

    /**
     * system_server 专用回调。
     * 只在这里安装 WindowOrganizerHook。
     */
    @Override
    public void onSystemServerStarting(
            XposedModuleInterface.SystemServerStartingParam param) {

        ClassLoader classLoader = param.getClassLoader();

        log(android.util.Log.INFO, TAG, "system_server 启动，安装入口拦截");

        try {
            WindowOrganizerHook.install(this, classLoader);
        } catch (Throwable t) {
            log(android.util.Log.ERROR, TAG,
                    "安装 WindowOrganizerHook 失败", t);
        }
    }

    /**
     * 普通应用进程回调。
     * 处理 SystemUI 和 Launcher。
     */
    @Override
    public void onPackageReady(
            XposedModuleInterface.PackageReadyParam param) {

        String packageName = param.getPackageName();
        ClassLoader classLoader = param.getClassLoader();

        // ===== SystemUI (WMShell) =====
        if ("com.android.systemui".equals(packageName)) {
            log(android.util.Log.INFO, TAG, "已加载到 SystemUI (WMShell)");
            try {
                SystemUIHook.install(this, classLoader);
            } catch (Throwable t) {
                log(android.util.Log.ERROR, TAG,
                        "安装 SystemUIHook 失败", t);
            }
            return;
        }

        // ===== Launcher =====
        try {
            LauncherProcessHook.install(this, classLoader, packageName);
        } catch (Throwable t) {
            log(android.util.Log.ERROR, TAG,
                    "安装 LauncherProcessHook 失败", t);
        }
    }
}
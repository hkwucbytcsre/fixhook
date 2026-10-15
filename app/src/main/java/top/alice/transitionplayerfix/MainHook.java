package top.alice.transitionplayerfix;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

import top.alice.transitionplayerfix.hook.LauncherProcessHook;
import top.alice.transitionplayerfix.hook.SystemUIHook;
import top.alice.transitionplayerfix.hook.WindowOrganizerHook;

/**
 * libxposed API 102 模块入口。
 *
 * 精简后的 Hook 分布（三层防御）：
 *   1. system_server → WindowOrganizerHook    入口拦截
 *   2. SystemUI      → SystemUIHook           参数校验（辅助）
 *   3. Launcher      → LauncherProcessHook    最终防线
 *
 * 已移除：
 *   - WindowManagerHook（与 SystemUIHook 功能重叠，不在攻击链上）
 *   - ActivityManagerHook（与漏洞利用链无关）
 */
public class MainHook extends XposedModule {

    private static final String TAG = "TransitionPlayerFix";

    @Override
    public void onPackageReady(
            XposedModuleInterface.PackageReadyParam param) {

        String packageName = param.getPackageName();
        ClassLoader classLoader = param.getClassLoader();

        // ===== system_server =====
        // LSPosed 中 system_server 的包名可能是 "android" 或 "system"
        if (isSystemServer(packageName)) {
            log(android.util.Log.INFO, TAG,
                    "已加载到 system_server (" + packageName + ")");

            try {
                WindowOrganizerHook.install(this, classLoader);
            } catch (Throwable t) {
                log(android.util.Log.ERROR, TAG,
                        "安装 WindowOrganizerHook 失败", t);
            }
            return;
        }

        // ===== SystemUI (WMShell) =====
        if ("com.android.systemui".equals(packageName)) {
            log(android.util.Log.INFO, TAG,
                    "已加载到 SystemUI (WMShell)");
            try {
                SystemUIHook.install(this, classLoader);
            } catch (Throwable t) {
                log(android.util.Log.ERROR, TAG,
                        "安装 SystemUIHook 失败", t);
            }
            return;
        }

        // ===== Launcher =====
        // LauncherProcessHook 内部会判断包名是否为 Launcher，
        // 不是则直接返回
        try {
            LauncherProcessHook.install(this, classLoader, packageName);
        } catch (Throwable t) {
            log(android.util.Log.ERROR, TAG,
                    "安装 LauncherProcessHook 失败", t);
        }
    }

    /**
     * system_server 在不同 LSPosed 版本中包名可能是 "android" 或 "system"。
     */
    private static boolean isSystemServer(String packageName) {
        return "android".equals(packageName) || "system".equals(packageName);
    }
}
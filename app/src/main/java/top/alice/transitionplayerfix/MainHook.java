package top.alice.transitionplayerfix;

import androidx.annotation.NonNull;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

import top.alice.transitionplayerfix.hook.WindowOrganizerHook;
import top.alice.transitionplayerfix.hook.WindowManagerHook;

/**
 * libxposed API 102 模块入口。
 *
 * 使用 onPackageReady 而非 onSystemServerStarting，原因：
 *   onSystemServerStarting 在系统服务启动早期触发，此时
 *   WindowOrganizerController 和 WindowManagerService 可能尚未被类加载。
 *   onPackageReady 在 AppComponentFactory 实例化类加载器之后触发，
 *   此时 system_server 的核心服务类已经就绪，Hook 成功率更高。
 *
 * 安装顺序：
 *   1. 先调用 WindowOrganizerHook.initContext() 提前缓存系统 Context，
 *      避免在 Hooker 内部进行脆弱的反射。
 *   2. 再安装两个 Hook。
 */
public class MainHook extends XposedModule {

    private static final String TAG = "TransitionPlayerFix";

    private static final String SYSTEM_SERVER_PROCESS = "system_server";

    @Override
    public void onPackageReady(
            @NonNull XposedModuleInterface.PackageReadyParam param) {

        // 仅处理 system_server 进程
        String processName = param.getProcessName();
        if (!SYSTEM_SERVER_PROCESS.equals(processName)) {
            return;
        }

        ClassLoader classLoader = param.getClassLoader();
        log(android.util.Log.INFO, TAG,
                "已加载到 system_server，开始安装官方补丁逻辑");

        // 第一步：提前初始化并缓存系统 Context
        try {
            WindowOrganizerHook.initContext(this, classLoader);
        } catch (Throwable t) {
            log(android.util.Log.ERROR, TAG,
                    "初始化 WindowOrganizerHook 的系统 Context 失败", t);
        }

        // 第二步：安装修复点一 —— registerTransitionPlayer 权限校验
        try {
            WindowOrganizerHook.install(this, classLoader);
        } catch (Throwable t) {
            log(android.util.Log.ERROR, TAG,
                    "安装 WindowOrganizerHook 失败", t);
        }

        // 第三步：安装修复点二 —— setRunningRemoteTransitionDelegate 参数类型收紧
        try {
            WindowManagerHook.install(this, classLoader);
        } catch (Throwable t) {
            log(android.util.Log.ERROR, TAG,
                    "安装 WindowManagerHook 失败", t);
        }
    }
}
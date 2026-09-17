package top.alice.transitionplayerfix.hook;

import android.os.Binder;

import androidx.annotation.NonNull;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * 对应官方补丁修复点二：
 * setRunningRemoteTransitionDelegate 的参数类型从 IBinder 收紧为 IApplicationThread，
 * 拒绝任意 IBinder 作为过渡委托。
 *
 * 异常模式说明：
 *   本 Hook 会主动抛出 SecurityException 阻止未授权调用，
 *   因此必须使用 PASSTHROUGH 模式（或默认模式），
 *   绝不能使用 PROTECTIVE 模式，否则异常会被框架吞掉，防护失效。
 */
public class WindowManagerHook {

    private static final String TAG = "TransitionPlayerFix";

    private static final String CLS_WINDOW_MANAGER_SERVICE =
            "com.android.server.wm.WindowManagerService";
    private static final String METHOD_SET_RUNNING_REMOTE_TRANSITION_DELEGATE =
            "setRunningRemoteTransitionDelegate";
    private static final String TYPE_I_APPLICATION_THREAD =
            "android.app.IApplicationThread";
    private static final String TYPE_IBINDER =
            "android.os.IBinder";

    public static void install(XposedModule module, ClassLoader classLoader) {
        try {
            Class<?> clazz = classLoader.loadClass(CLS_WINDOW_MANAGER_SERVICE);

            Method method = null;
            for (Method m : clazz.getDeclaredMethods()) {
                if (METHOD_SET_RUNNING_REMOTE_TRANSITION_DELEGATE.equals(m.getName())
                        && m.getParameterCount() == 1) {
                    String paramType = m.getParameterTypes()[0].getName();
                    // 精确匹配 IBinder（漏洞版本签名）或 IApplicationThread（修复版本签名）
                    if (TYPE_IBINDER.equals(paramType)
                            || TYPE_I_APPLICATION_THREAD.equals(paramType)) {
                        method = m;
                        break;
                    }
                }
            }

            if (method == null) {
                module.log(android.util.Log.WARN, TAG,
                        "未找到 setRunningRemoteTransitionDelegate 方法");
                return;
            }

            module.log(android.util.Log.INFO, TAG,
                    "找到方法: " + method);

            // 关键：使用 PASSTHROUGH 模式，确保主动抛出的 SecurityException 能传播
            module.hook(method)
                    .setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
                    .intercept(new DelegateTypeCheckHooker(module, classLoader));

            module.log(android.util.Log.INFO, TAG,
                    "已 Hook setRunningRemoteTransitionDelegate");
        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook setRunningRemoteTransitionDelegate 失败", t);
        }
    }

    private static class DelegateTypeCheckHooker implements XposedInterface.Hooker {

        private final XposedModule module;
        private final ClassLoader classLoader;

        DelegateTypeCheckHooker(XposedModule module, ClassLoader classLoader) {
            this.module = module;
            this.classLoader = classLoader;
        }

        @Override
        public Object intercept(@NonNull XposedInterface.Chain chain) throws Throwable {
            Object arg = chain.getArgs().get(0);
            if (arg == null) {
                return chain.proceed();
            }

            if (!isIApplicationThread(arg, classLoader)) {
                int callingUid = Binder.getCallingUid();
                module.log(android.util.Log.WARN, TAG,
                        "拒绝非 IApplicationThread 的过渡委托参数: "
                                + arg.getClass().getName()
                                + " (callingUid=" + callingUid + ")");
                throw new SecurityException(
                        "setRunningRemoteTransitionDelegate requires "
                                + "IApplicationThread (uid=" + callingUid + ")");
            }

            return chain.proceed();
        }
    }

    private static boolean isIApplicationThread(Object obj, ClassLoader classLoader) {
        try {
            Class<?> appThreadClass = classLoader.loadClass(TYPE_I_APPLICATION_THREAD);
            return appThreadClass.isInstance(obj);
        } catch (Throwable t) {
            String name = obj.getClass().getName();
            return TYPE_I_APPLICATION_THREAD.equals(name)
                    || name.startsWith(TYPE_I_APPLICATION_THREAD + "$");
        }
    }
}
package top.alice.transitionplayerfix.hook;

import android.os.Build;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

public class SystemUIHook {

    private static final String TAG = "TransitionPlayerFix";
    private static final String CLS_TRANSITIONS =
            "com.android.wm.shell.transition.Transitions";
    private static final String METHOD_SET_DELEGATE =
            "setRunningRemoteTransitionDelegate";
    private static final String TYPE_I_APPLICATION_THREAD =
            "android.app.IApplicationThread";
    private static final String TYPE_IBINDER = "android.os.IBinder";

    /** 缓存的 IApplicationThread Class，避免每次 Hook 回调重复加载 */
    private static volatile Class<?> sIApplicationThreadClass;

    public static void install(XposedModule module, ClassLoader classLoader) {
        if (Build.VERSION.SDK_INT >= 37) {
            module.log(android.util.Log.INFO, TAG,
                    "Android 17+ 已原生加固，跳过 SystemUIHook");
            return;
        }

        try {
            // 在 install 阶段缓存 Class 对象
            sIApplicationThreadClass =
                    classLoader.loadClass(TYPE_I_APPLICATION_THREAD);
            module.log(android.util.Log.INFO, TAG,
                    "已缓存 IApplicationThread Class");

            Class<?> clazz = classLoader.loadClass(CLS_TRANSITIONS);

            Method target = null;
            for (Method m : clazz.getDeclaredMethods()) {
                if (METHOD_SET_DELEGATE.equals(m.getName())
                        && m.getParameterCount() == 1) {
                    String paramType = m.getParameterTypes()[0].getName();
                    if (TYPE_IBINDER.equals(paramType)
                            || TYPE_I_APPLICATION_THREAD.equals(paramType)) {
                        target = m;
                        break;
                    }
                }
            }

            if (target == null) {
                module.log(android.util.Log.WARN, TAG,
                        "未找到 setRunningRemoteTransitionDelegate");
                return;
            }

            module.hook(target)
                    .setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
                    .intercept(new DelegateTypeHooker(module));

            module.log(android.util.Log.INFO, TAG,
                    "已 Hook setRunningRemoteTransitionDelegate");

        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG, "SystemUIHook 失败", t);
        }
    }

    private static class DelegateTypeHooker implements XposedInterface.Hooker {

        private final XposedModule module;

        DelegateTypeHooker(XposedModule module) {
            this.module = module;
        }

        @Override
        public Object intercept(XposedInterface.Chain chain) throws Throwable {
            try {
                Object arg = chain.getArg(0);
                if (arg == null) {
                    return chain.proceed();
                }

                // 使用缓存的 Class 对象，避免重复 loadClass
                Class<?> iAppThreadClass = sIApplicationThreadClass;
                if (iAppThreadClass == null) {
                    module.log(android.util.Log.WARN, TAG,
                            "IApplicationThread Class 缓存为空，放行");
                    return chain.proceed();
                }

                if (!iAppThreadClass.isInstance(arg)) {
                    module.log(android.util.Log.WARN, TAG,
                            "拒绝非 IApplicationThread 的过渡委托: "
                                    + arg.getClass().getName());
                    throw new SecurityException(
                            "setRunningRemoteTransitionDelegate requires "
                                    + "IApplicationThread, got "
                                    + arg.getClass().getName());
                }

                return chain.proceed();

            } catch (SecurityException se) {
                throw se;
            } catch (Throwable t) {
                module.log(android.util.Log.ERROR, TAG,
                        "Hook 内部错误，放行避免崩溃", t);
            }
            return chain.proceed();
        }
    }
}
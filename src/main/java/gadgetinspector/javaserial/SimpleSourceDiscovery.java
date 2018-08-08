package gadgetinspector.javaserial;

import gadgetinspector.SerializableDecider;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.data.Source;
import org.objectweb.asm.Type;

import java.util.Map;

public class SimpleSourceDiscovery extends SourceDiscovery {

    @Override
    public void discover(Map<ClassReference.Handle, ClassReference> classMap,
                         Map<MethodReference.Handle, MethodReference> methodMap,
                         InheritanceMap inheritanceMap) {

        final SerializableDecider serializableDecider = new SimpleSerializableDecider(inheritanceMap);

        for (MethodReference.Handle method : methodMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))) {
                if (method.getName().equals("finalize") && method.getDesc().equals("()V")) {
                    addDiscoveredSource(new Source(method, 0));
                }
            }
        }

        // If a class implements readObject, the ObjectInputStream passed in is considered tainted
        for (MethodReference.Handle method : methodMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))) {
                if (method.getName().equals("readObject") && method.getDesc().equals("(Ljava/io/ObjectInputStream;)V")) {
                    addDiscoveredSource(new Source(method, 1));
                }
            }
        }

        // Using the proxy trick, anything extending serializable and invocation handler is tainted.
        for (ClassReference.Handle clazz : classMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(clazz))
                    && inheritanceMap.isSubclassOf(clazz, new ClassReference.Handle("java/lang/reflect/InvocationHandler"))) {
                MethodReference.Handle method = new MethodReference.Handle(
                        clazz, "invoke", "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;");

                addDiscoveredSource(new Source(method, 0));
            }
        }

        // hashCode() or equals() are accessible entry points using standard tricks of putting those objects
        // into a HashMap.
        for (MethodReference.Handle method : methodMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))) {
                if (method.getName().equals("hashCode") && method.getDesc().equals("()I")) {
                    addDiscoveredSource(new Source(method, 0));
                }
                if (method.getName().equals("equals") && method.getDesc().equals("(Ljava/lang/Object;)Z")) {
                    addDiscoveredSource(new Source(method, 0));
                    addDiscoveredSource(new Source(method, 1));
                }
            }
        }

        // Using a comparator proxy, we can jump into the call() / doCall() method of any groovy Closure and all the
        // args are tainted.
        // https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Groovy1.java
        for (MethodReference.Handle method : methodMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))
                    && inheritanceMap.isSubclassOf(method.getClassReference(), new ClassReference.Handle("groovy/lang/Closure"))
                    && (method.getName().equals("call") || method.getName().equals("doCall"))) {

                addDiscoveredSource(new Source(method, 0));
                Type[] methodArgs = Type.getArgumentTypes(method.getDesc());
                for (int i = 0; i < methodArgs.length; i++) {
                    addDiscoveredSource(new Source(method, i + 1));
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SourceDiscovery sourceDiscovery = new SimpleSourceDiscovery();
        sourceDiscovery.discover();
        sourceDiscovery.save();
    }
}

package gadgetinspector.jackson;

import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.data.Source;

import java.util.Map;

public class JacksonSourceDiscovery extends SourceDiscovery {

    @Override
    public void discover(Map<ClassReference.Handle, ClassReference> classMap,
                         Map<MethodReference.Handle, MethodReference> methodMap,
                         InheritanceMap inheritanceMap) {

        final JacksonSerializableDecider serializableDecider = new JacksonSerializableDecider(methodMap);

        for (MethodReference.Handle method : methodMap.keySet()) {
            if (serializableDecider.apply(method.getClassReference())) {
                if (method.getName().equals("<init>") && method.getDesc().equals("()V")) {
                    addDiscoveredSource(new Source(method, 0));
                }
                if (method.getName().startsWith("get") && method.getDesc().startsWith("()")) {
                    addDiscoveredSource(new Source(method, 0));
                }
                if (method.getName().startsWith("set") && method.getDesc().matches("\\(L[^;]*;\\)V")) {
                    addDiscoveredSource(new Source(method, 0));
                }
            }
        }
    }

}

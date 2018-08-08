package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.jackson.JacksonImplementationFinder;
import gadgetinspector.jackson.JacksonSerializableDecider;
import gadgetinspector.jackson.JacksonSourceDiscovery;

import java.util.Map;
import java.util.Set;

public class JacksonDeserializationConfig implements GIConfig {

    @Override
    public String getName() {
        return "jackson";
    }

    @Override
    public ImplementationFinder getImplementationFinder(Map<MethodReference.Handle, MethodReference> methodMap,
                                                        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap,
                                                        InheritanceMap inheritanceMap) {
        return new JacksonImplementationFinder(new JacksonSerializableDecider(methodMap));
    }

    @Override
    public SourceDiscovery getSourceDiscovery() {
        return new JacksonSourceDiscovery();
    }
}

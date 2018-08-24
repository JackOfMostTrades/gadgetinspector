package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.javaserial.SimpleImplementationFinder;
import gadgetinspector.javaserial.SimpleSourceDiscovery;
import gadgetinspector.xstream.XstreamSerializableDecider;

import java.util.Map;
import java.util.Set;

public class XstreamDeserializationConfig implements GIConfig {
    @Override
    public String getName() {
        return "xstream";
    }

    public SerializableDecider getSerializableDecider(Map<MethodReference.Handle, MethodReference> methodMap, InheritanceMap inheritanceMap) {
        return new XstreamSerializableDecider();
    }

    @Override
    public ImplementationFinder getImplementationFinder(Map<MethodReference.Handle, MethodReference> methodMap,
                                                        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap,
                                                        InheritanceMap inheritanceMap) {
        return new SimpleImplementationFinder(getSerializableDecider(methodMap, inheritanceMap), methodImplMap);
    }

    @Override
    public SourceDiscovery getSourceDiscovery() {
        return new SimpleSourceDiscovery();
    }

}

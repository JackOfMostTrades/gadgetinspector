package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;

import java.util.Map;
import java.util.Set;

public interface GIConfig {

    String getName();
    ImplementationFinder getImplementationFinder(Map<MethodReference.Handle, MethodReference> methodMap,
                                                 Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap,
                                                 InheritanceMap inheritanceMap);
    SourceDiscovery getSourceDiscovery();

}

package gadgetinspector;

import gadgetinspector.data.*;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/* FIXME: This source discovery is limited to standard serializable objects; doesn't do proper source discovery for
 * non-standard Xstream cases. */
public abstract class SourceDiscovery {

    private final List<Source> discoveredSources = new ArrayList<>();

    protected final void addDiscoveredSource(Source source) {
        discoveredSources.add(source);
    }

    public void discover() throws IOException {
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        InheritanceMap inheritanceMap = InheritanceMap.load();

        discover(classMap, methodMap, inheritanceMap);
    }

    public abstract void discover(Map<ClassReference.Handle, ClassReference> classMap,
                         Map<MethodReference.Handle, MethodReference> methodMap,
                         InheritanceMap inheritanceMap);

    public void save() throws IOException {
        DataLoader.saveData(Paths.get("sources.dat"), new Source.Factory(), discoveredSources);
    }
}

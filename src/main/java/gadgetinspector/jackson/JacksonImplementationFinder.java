package gadgetinspector.jackson;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.data.MethodReference;

import java.util.HashSet;
import java.util.Set;

public class JacksonImplementationFinder implements ImplementationFinder {

    private final SerializableDecider serializableDecider;

    public JacksonImplementationFinder(SerializableDecider serializableDecider) {
        this.serializableDecider = serializableDecider;
    }

    @Override
    public Set<MethodReference.Handle> getImplementations(MethodReference.Handle target) {
        Set<MethodReference.Handle> allImpls = new HashSet<>();

        // For jackson search, we don't get to specify the class; it uses reflection to instantiate the
        // class itself. So just add the target method if the target class is serializable.
        if (Boolean.TRUE.equals(serializableDecider.apply(target.getClassReference()))) {
            allImpls.add(target);
        }

        return allImpls;
    }
}

package gadgetinspector.xstream;

import gadgetinspector.SerializableDecider;
import gadgetinspector.data.ClassReference;

import java.util.*;

/**
 * Represents a custom serializability decider that implements some complex constraints in one application that was
 * evaluated. This helps illustrate the sort of mitigations which look constraining enough to prevent attacks but are
 * still insufficient.
 */
public class CustomXstreamSerializableDecider implements SerializableDecider {
    private final Map<ClassReference.Handle, Boolean> serializableMap = new HashMap<>();
    private final Map<ClassReference.Handle, ClassReference> classMap;
    private final Map<ClassReference.Handle, Set<ClassReference.Handle>> inheritanceMap;

    public CustomXstreamSerializableDecider(Map<ClassReference.Handle, ClassReference> classMap,
                                            Map<ClassReference.Handle, Set<ClassReference.Handle>> inheritanceMap) {
        this.classMap = classMap;
        this.inheritanceMap = inheritanceMap;
    }

    @Override
    public Boolean apply(ClassReference.Handle handle) {
        List<ClassReference.Handle> circularRefList = new ArrayList<>();
        Boolean result = isSerializable(handle, circularRefList);
        if (circularRefList.size() != 0) {
            throw new IllegalStateException();
        }
        return result;
    }

    private boolean isSerializable(ClassReference.Handle clazz, List<ClassReference.Handle> circularRefList) {
        Boolean serializable = serializableMap.get(clazz);
        if (serializable != null) {
            return serializable.booleanValue();
        }

        if (circularRefList.contains(clazz)) {
            serializableMap.put(clazz, Boolean.FALSE);
            return false;
        }

        if (clazz.getName().equals("java/lang/String")) {
            serializableMap.put(clazz, Boolean.TRUE);
            return true;
        }

        if (clazz.getName().charAt(0) == '[' || clazz.getName().equals("java/lang/Class")) {
            serializableMap.put(clazz, Boolean.FALSE);
            return false;
        }

        ClassReference classReference = classMap.get(clazz);
        if (classReference == null) {
            serializableMap.put(clazz, Boolean.TRUE);
            return true;
        }

        circularRefList.add(clazz);
        try {
            for (ClassReference.Member member : classReference.getMembers()) {
                if (member.getName().contains("$")) {
                    serializableMap.put(clazz, Boolean.FALSE);
                    return false;
                }

                if (!isSerializable(member.getType(), circularRefList)) {
                    serializableMap.put(clazz, Boolean.FALSE);
                    return false;
                }
            }
            for (ClassReference.Handle superClass : inheritanceMap.get(clazz)) {
                if (!isSerializable(superClass, circularRefList)) {
                    serializableMap.put(clazz, Boolean.FALSE);
                    return false;
                }
            }
        } finally {
            circularRefList.remove(circularRefList.size()-1);
        }

        serializableMap.put(clazz, Boolean.TRUE);
        return true;
    }
}

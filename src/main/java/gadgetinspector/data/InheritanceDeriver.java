package gadgetinspector.data;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InheritanceDeriver {
    private static final Logger LOGGER = LoggerFactory.getLogger(InheritanceDeriver.class);

    public static InheritanceMap derive(Map<ClassReference.Handle, ClassReference> classMap) {
        LOGGER.debug("Calculating inheritance for " + (classMap.size()) + " classes...");
        Map<ClassReference.Handle, Set<ClassReference.Handle>> implicitInheritance = new HashMap<>();
        for (ClassReference classReference : classMap.values()) {
            if (implicitInheritance.containsKey(classReference.getHandle())) {
                throw new IllegalStateException("Already derived implicit classes for " + classReference.getName());
            }
            Set<ClassReference.Handle> allParents = new HashSet<>();

            getAllParents(classReference, classMap, allParents);

            implicitInheritance.put(classReference.getHandle(), allParents);
        }
        return new InheritanceMap(implicitInheritance);
    }

    private static void getAllParents(ClassReference classReference, Map<ClassReference.Handle, ClassReference> classMap, Set<ClassReference.Handle> allParents) {
        Set<ClassReference.Handle> parents = new HashSet<>();
        if (classReference.getSuperClass() != null) {
            parents.add(new ClassReference.Handle(classReference.getSuperClass()));
        }
        for (String iface : classReference.getInterfaces()) {
            parents.add(new ClassReference.Handle(iface));
        }

        for (ClassReference.Handle immediateParent : parents) {
            ClassReference parentClassReference = classMap.get(immediateParent);
            if (parentClassReference == null) {
                LOGGER.debug("No class id for " + immediateParent.getName());
                continue;
            }
            allParents.add(parentClassReference.getHandle());
            getAllParents(parentClassReference, classMap, allParents);
        }
    }

    public static Map<MethodReference.Handle, Set<MethodReference.Handle>> getAllMethodImplementations(
            InheritanceMap inheritanceMap, Map<MethodReference.Handle, MethodReference> methodMap) {

        Map<ClassReference.Handle, Set<MethodReference.Handle>> methodsByClass = new HashMap<>();
        for (MethodReference.Handle method : methodMap.keySet()) {
            ClassReference.Handle classReference = method.getClassReference();
            if (!methodsByClass.containsKey(classReference)) {
                Set<MethodReference.Handle> methods = new HashSet<>();
                methods.add(method);
                methodsByClass.put(classReference, methods);
            } else {
                methodsByClass.get(classReference).add(method);
            }
        }

        Map<ClassReference.Handle, Set<ClassReference.Handle>> subClassMap = new HashMap<>();
        for (Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>> entry : inheritanceMap.entrySet()) {
            for (ClassReference.Handle parent : entry.getValue()) {
                if (!subClassMap.containsKey(parent)) {
                    Set<ClassReference.Handle> subClasses = new HashSet<>();
                    subClasses.add(entry.getKey());
                    subClassMap.put(parent, subClasses);
                } else {
                    subClassMap.get(parent).add(entry.getKey());
                }
            }
        }

        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap = new HashMap<>();
        for (MethodReference method : methodMap.values()) {
            // Static methods cannot be overriden
            if (method.isStatic()) {
                continue;
            }

            Set<MethodReference.Handle> overridingMethods = new HashSet<>();
            Set<ClassReference.Handle> subClasses = subClassMap.get(method.getClassReference());
            if (subClasses != null) {
                for (ClassReference.Handle subClass : subClasses) {
                    // This class extends ours; see if it has a matching method
                    Set<MethodReference.Handle> subClassMethods = methodsByClass.get(subClass);
                    if (subClassMethods != null) {
                        for (MethodReference.Handle subClassMethod : subClassMethods) {
                            if (subClassMethod.getName().equals(method.getName()) && subClassMethod.getDesc().equals(method.getDesc())) {
                                overridingMethods.add(subClassMethod);
                            }
                        }
                    }
                }
            }

            if (overridingMethods.size() > 0) {
                methodImplMap.put(method.getHandle(), overridingMethods);
            }
        }

        return methodImplMap;
    }
}

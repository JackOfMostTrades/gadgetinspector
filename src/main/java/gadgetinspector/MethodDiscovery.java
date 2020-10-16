package gadgetinspector;

import gadgetinspector.data.ClassReference;
import gadgetinspector.data.DataLoader;
import gadgetinspector.data.InheritanceDeriver;
import gadgetinspector.data.MethodReference;
import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MethodDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodDiscovery.class);

    private final List<ClassReference> discoveredClasses = new ArrayList<>();
    private final List<MethodReference> discoveredMethods = new ArrayList<>();

    public void save() throws IOException {
        DataLoader.saveData(Paths.get("classes.dat"), new ClassReference.Factory(), discoveredClasses);
        DataLoader.saveData(Paths.get("methods.dat"), new MethodReference.Factory(), discoveredMethods);

        Map<ClassReference.Handle, ClassReference> classMap = new HashMap<>();
        for (ClassReference clazz : discoveredClasses) {
            classMap.put(clazz.getHandle(), clazz);
        }
        InheritanceDeriver.derive(classMap).save();
    }

    public void discover(final ClassResourceEnumerator classResourceEnumerator) throws Exception {
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
                try {
                    cr.accept(new MethodDiscoveryClassVisitor(), ClassReader.EXPAND_FRAMES);
                } catch (Exception e) {
                    LOGGER.error("Exception analyzing: " + classResource.getName(), e);
                }
            }
        }
    }

    private class MethodDiscoveryClassVisitor extends ClassVisitor {

        private String name;
        private String superName;
        private String[] interfaces;
        boolean isInterface;
        private List<ClassReference.Member> members;
        private ClassReference.Handle classHandle;

        private MethodDiscoveryClassVisitor() throws SQLException {
            super(Opcodes.ASM7);
        }

        @Override
        public void visit ( int version, int access, String name, String signature, String superName, String[]interfaces)
        {
            this.name = name;
            this.superName = superName;
            this.interfaces = interfaces;
            this.isInterface = (access & Opcodes.ACC_INTERFACE) != 0;
            this.members = new ArrayList<>();
            this.classHandle = new ClassReference.Handle(name);

            super.visit(version, access, name, signature, superName, interfaces);
        }

        public FieldVisitor visitField(int access, String name, String desc,
                                       String signature, Object value) {
            if ((access & Opcodes.ACC_STATIC) == 0) {
                Type type = Type.getType(desc);
                String typeName;
                if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
                    typeName = type.getInternalName();
                } else {
                    typeName = type.getDescriptor();
                }
                members.add(new ClassReference.Member(name, access, new ClassReference.Handle(typeName)));
            }
            return super.visitField(access, name, desc, signature, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
            discoveredMethods.add(new MethodReference(
                    classHandle,
                    name,
                    desc,
                    isStatic));
            return super.visitMethod(access, name, desc, signature, exceptions);
        }

        @Override
        public void visitEnd() {
            ClassReference classReference = new ClassReference(
                    name,
                    superName,
                    interfaces,
                    isInterface,
                    members.toArray(new ClassReference.Member[members.size()]));
            discoveredClasses.add(classReference);

            super.visitEnd();
        }

    }

    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = new URLClassLoader(Util.getExplodedWarURLs(Paths.get(args[0])).toArray(new URL[0]));

        MethodDiscovery methodDiscovery = new MethodDiscovery();
        methodDiscovery.discover(new ClassResourceEnumerator(classLoader));
        methodDiscovery.save();
    }
}

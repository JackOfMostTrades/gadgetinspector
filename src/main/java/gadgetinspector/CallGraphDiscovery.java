package gadgetinspector;

import gadgetinspector.config.GIConfig;
import gadgetinspector.config.JavaDeserializationConfig;
import gadgetinspector.data.*;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CallGraphDiscovery {
    private static final Logger LOGGER = LoggerFactory.getLogger(CallGraphDiscovery.class);

    private final Set<GraphCall> discoveredCalls = new HashSet<>();

    public void discover(final ClassResourceEnumerator classResourceEnumerator, GIConfig config) throws IOException {
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        InheritanceMap inheritanceMap = InheritanceMap.load();
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = PassthroughDiscovery.load();

        SerializableDecider serializableDecider = config.getSerializableDecider(methodMap, inheritanceMap);

        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
                try {
                    cr.accept(new ModelGeneratorClassVisitor(classMap, inheritanceMap, passthroughDataflow, serializableDecider, Opcodes.ASM7),
                            ClassReader.EXPAND_FRAMES);
                } catch (Exception e) {
                    LOGGER.error("Error analyzing: " + classResource.getName(), e);
                }
            }
        }
    }

    public void save() throws IOException {
        DataLoader.saveData(Paths.get("callgraph.dat"), new GraphCall.Factory(), discoveredCalls);
    }

    private class ModelGeneratorClassVisitor extends ClassVisitor {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final SerializableDecider serializableDecider;

        public ModelGeneratorClassVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                          InheritanceMap inheritanceMap,
                                          Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                          SerializableDecider serializableDecider, int api) {
            super(api);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDecider;
        }

        private String name;
        private String signature;
        private String superName;
        private String[] interfaces;

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
            this.signature = signature;
            this.superName = superName;
            this.interfaces = interfaces;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            ModelGeneratorMethodVisitor modelGeneratorMethodVisitor = new ModelGeneratorMethodVisitor(classMap,
                    inheritanceMap, passthroughDataflow, serializableDecider, api, mv, this.name, access, name, desc, signature, exceptions);

            return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
        }

        @Override
        public void visitOuterClass(String owner, String name, String desc) {
            // TODO: Write some tests to make sure we can ignore this
            super.visitOuterClass(owner, name, desc);
        }

        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {
            // TODO: Write some tests to make sure we can ignore this
            super.visitInnerClass(name, outerName, innerName, access);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
        }
    }

    private class ModelGeneratorMethodVisitor extends TaintTrackingMethodVisitor<String> {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final SerializableDecider serializableDecider;
        private final String owner;
        private final int access;
        private final String name;
        private final String desc;

        public ModelGeneratorMethodVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                           InheritanceMap inheritanceMap,
                                           Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                           SerializableDecider serializableDecider, final int api, final MethodVisitor mv,
                                           final String owner, int access, String name, String desc, String signature,
                                           String[] exceptions) {
            super(inheritanceMap, passthroughDataflow, api, mv, owner, access, name, desc, signature, exceptions);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.serializableDecider = serializableDecider;
            this.owner = owner;
            this.access = access;
            this.name = name;
            this.desc = desc;
        }

        @Override
        public void visitCode() {
            super.visitCode();

            int localIndex = 0;
            int argIndex = 0;
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            for (Type argType : Type.getArgumentTypes(desc)) {
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {

            switch (opcode) {
                case Opcodes.GETSTATIC:
                    break;
                case Opcodes.PUTSTATIC:
                    break;
                case Opcodes.GETFIELD:
                    Type type = Type.getType(desc);
                    if (type.getSize() == 1) {
                        Boolean isTransient = null;

                        // If a field type could not possibly be serialized, it's effectively transient
                        if (!couldBeSerialized(serializableDecider, inheritanceMap, new ClassReference.Handle(type.getInternalName()))) {
                            isTransient = Boolean.TRUE;
                        } else {
                            ClassReference clazz = classMap.get(new ClassReference.Handle(owner));
                            while (clazz != null) {
                                for (ClassReference.Member member : clazz.getMembers()) {
                                    if (member.getName().equals(name)) {
                                        isTransient = (member.getModifiers() & Opcodes.ACC_TRANSIENT) != 0;
                                        break;
                                    }
                                }
                                if (isTransient != null) {
                                    break;
                                }
                                clazz = classMap.get(new ClassReference.Handle(clazz.getSuperClass()));
                            }
                        }

                        Set<String> newTaint = new HashSet<>();
                        if (!Boolean.TRUE.equals(isTransient)) {
                            for (String s : getStackTaint(0)) {
                                newTaint.add(s + "." + name);
                            }
                        }
                        super.visitFieldInsn(opcode, owner, name, desc);
                        setStackTaint(0, newTaint);
                        return;
                    }
                    break;
                case Opcodes.PUTFIELD:
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            super.visitFieldInsn(opcode, owner, name, desc);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            Type[] argTypes = Type.getArgumentTypes(desc);
            if (opcode != Opcodes.INVOKESTATIC) {
                Type[] extendedArgTypes = new Type[argTypes.length+1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);
                argTypes = extendedArgTypes;
            }

            switch (opcode) {
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
                case Opcodes.INVOKEINTERFACE:
                    int stackIndex = 0;
                    for (int i = 0; i < argTypes.length; i++) {
                        int argIndex = argTypes.length-1-i;
                        Type type = argTypes[argIndex];
                        Set<String> taint = getStackTaint(stackIndex);
                        if (taint.size() > 0) {
                            for (String argSrc : taint) {
                                if (!argSrc.startsWith("arg")) {
                                    throw new IllegalStateException("Invalid taint arg: " + argSrc);
                                }
                                int dotIndex = argSrc.indexOf('.');
                                int srcArgIndex;
                                String srcArgPath;
                                if (dotIndex == -1) {
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3));
                                    srcArgPath = null;
                                } else {
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3, dotIndex));
                                    srcArgPath = argSrc.substring(dotIndex+1);
                                }

                                discoveredCalls.add(new GraphCall(
                                        new MethodReference.Handle(new ClassReference.Handle(this.owner), this.name, this.desc),
                                        new MethodReference.Handle(new ClassReference.Handle(owner), name, desc),
                                        srcArgIndex,
                                        srcArgPath,
                                        argIndex));
                            }
                        }

                        stackIndex += type.getSize();
                    }
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }

    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = new URLClassLoader(Util.getExplodedWarURLs(Paths.get(args[0])).toArray(new URL[0]));

        CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
        callGraphDiscovery.discover(new ClassResourceEnumerator(classLoader), new JavaDeserializationConfig());
        callGraphDiscovery.save();
    }
}

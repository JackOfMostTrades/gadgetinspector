package gadgetinspector.data;

public class ClassReference {
    private final String name;
    private final String superClass;
    private final String[] interfaces;
    private final boolean isInterface;
    private final Member[] members;

    public static class Member {
        private final String name;
        private final int modifiers;
        private final ClassReference.Handle type;

        public Member(String name, int modifiers, Handle type) {
            this.name = name;
            this.modifiers = modifiers;
            this.type = type;
        }

        public String getName() {
            return name;
        }

        public int getModifiers() {
            return modifiers;
        }

        public Handle getType() {
            return type;
        }
    }

    public ClassReference(String name, String superClass, String[] interfaces, boolean isInterface, Member[] members) {
        this.name = name;
        this.superClass = superClass;
        this.interfaces = interfaces;
        this.isInterface = isInterface;
        this.members = members;
    }

    public String getName() {
        return name;
    }

    public String getSuperClass() {
        return superClass;
    }

    public String[] getInterfaces() {
        return interfaces;
    }

    public boolean isInterface() {
        return isInterface;
    }

    public Member[] getMembers() {
        return members;
    }

    public Handle getHandle() {
        return new Handle(name);
    }

    public static class Handle {
        private final String name;

        public Handle(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Handle handle = (Handle) o;

            return name != null ? name.equals(handle.name) : handle.name == null;
        }

        @Override
        public int hashCode() {
            return name != null ? name.hashCode() : 0;
        }
    }

    public static class Factory implements DataFactory<ClassReference> {

        @Override
        public ClassReference parse(String[] fields) {
            String[] interfaces;
            if (fields[2].equals("")) {
                interfaces = new String[0];
            } else {
                interfaces = fields[2].split(",");
            }

            String[] memberEntries = fields[4].split("!");
            Member[] members = new Member[memberEntries.length/3];
            for (int i = 0; i < members.length; i++) {
                members[i] = new Member(memberEntries[3*i], Integer.parseInt(memberEntries[3*i+1]),
                        new ClassReference.Handle(memberEntries[3*i+2]));
            }

            return new ClassReference(
                    fields[0],
                    fields[1].equals("") ? null : fields[1],
                    interfaces,
                    Boolean.parseBoolean(fields[3]),
                    members);
        }

        @Override
        public String[] serialize(ClassReference obj) {
            String interfaces;
            if (obj.interfaces.length > 0) {
                StringBuilder interfacesSb = new StringBuilder();
                for (String iface : obj.interfaces) {
                    interfacesSb.append(",").append(iface);
                }
                interfaces = interfacesSb.substring(1);
            } else {
                interfaces = "";
            }

            StringBuilder members = new StringBuilder();
            for (Member member : obj.members) {
                members.append("!").append(member.getName())
                        .append("!").append(Integer.toString(member.getModifiers()))
                        .append("!").append(member.getType().getName());
            }

            return new String[]{
                    obj.name,
                    obj.superClass,
                    interfaces,
                    Boolean.toString(obj.isInterface),
                    members.length() == 0 ? null : members.substring(1)
            };
        }
    }
}

package gadgetinspector.data;

public class Source {
    private final MethodReference.Handle sourceMethod;
    private final int taintedArgIndex;

    public Source(MethodReference.Handle sourceMethod,int taintedArgIndex) {
        this.sourceMethod = sourceMethod;
        this.taintedArgIndex = taintedArgIndex;
    }

    public MethodReference.Handle getSourceMethod() {
        return sourceMethod;
    }

    public int getTaintedArgIndex() {
        return taintedArgIndex;
    }

    public static class Factory implements DataFactory<Source> {

        @Override
        public Source parse(String[] fields) {
            return new Source(
                    new MethodReference.Handle(new ClassReference.Handle(fields[0]), fields[1], fields[2]),
                    Integer.parseInt(fields[3])
            );
        }

        @Override
        public String[] serialize(Source obj) {
            return new String[]{
                    obj.sourceMethod.getClassReference().getName(), obj.sourceMethod.getName(), obj.sourceMethod.getDesc(),
                    Integer.toString(obj.taintedArgIndex),
            };
        }
    }
}

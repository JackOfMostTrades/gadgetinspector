package gadgetinspector;

import gadgetinspector.data.MethodReference;

class GadgetChainLink {
   public final MethodReference.Handle method;
   public final int taintedArgIndex;

   GadgetChainLink(MethodReference.Handle method, int taintedArgIndex) {
      this.method = method;
      this.taintedArgIndex = taintedArgIndex;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      GadgetChainLink that = (GadgetChainLink) o;

      if (taintedArgIndex != that.taintedArgIndex) return false;
      return method != null ? method.equals(that.method) : that.method == null;
   }

   @Override
   public int hashCode() {
      int result = method != null ? method.hashCode() : 0;
      result = 31 * result + taintedArgIndex;
      return result;
   }
}

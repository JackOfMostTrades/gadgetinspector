package gadgetinspector;

import gadgetinspector.data.ClassReference;
import gadgetinspector.javaserial.SimpleSerializableDecider;

import java.util.function.Function;

/**
 * Represents logic to decide if a class is serializable. The simple case (implemented by
 * {@link SimpleSerializableDecider}) just checks if the class implements serializable. Other use-cases may have more
 * complicated logic.
 */
public interface SerializableDecider extends Function<ClassReference.Handle, Boolean> {
}

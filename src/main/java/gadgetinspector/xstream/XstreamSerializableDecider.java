package gadgetinspector.xstream;

import gadgetinspector.SerializableDecider;
import gadgetinspector.data.ClassReference;

/**
 * The default behavior of xstream is to support xml tags as specifying arbitrary class names. So a class is serializable
 * if the class name is a valid XML tag.
 */
public class XstreamSerializableDecider implements SerializableDecider {

    @Override
    public Boolean apply(ClassReference.Handle handle) {
        return isValidXmlTag(handle.getName().replace('/', '.'));
    }

    private static boolean isValidXmlTag(String name) {
        // Name ::= NameStartChar (NameChar)*
        if (name == null || name.length() == 0) {
            return false;
        }
        if (!isNameStartChar(name.charAt(0))) {
            return false;
        }
        for (int i = 1; i < name.length(); i++) {
            if (!isNameChar(name.charAt(i))) {
                return false;
            }
        }
        return true;
    }
    
    private static boolean isNameStartChar(char c) {
        // NameStartChar ::= ":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] | [#x370-#x37D] | [#x37F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] | [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]
        if (c == ':' || ('A' <= c && c <= 'Z') || c == '_' || ('a' <= c && c <= 'z')
                || (0xC0 <= c && c <= 0xD6) || (0xD8 <= c && c <= 0xF6) || (0xF8 <= c && c <= 0x2FF)
                || (0x370 <= c && c <= 0x37D) || (0x37F <= c && c <= 0x1FFF) || (0x200C <= c && c <= 0x200D)
                || (0x2070 <= c && c <= 0x218F) || (0x2C00 <= c && c <= 0x2FEF) || (0x3001 <= c && c <= 0xD7FF)
                || (0xF900 <= c && c <= 0xFDCF) || (0xFDF0 <= c && c <= 0xFFFD)) {
            return true;
        }
        return false;
    }
    
    private static boolean isNameChar(char c) {
        // NameChar ::= NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] | [#x203F-#x2040]
        if (isNameStartChar(c) || c == '-' || c == '.' || ('0' <= c && c <= '9') || c == 0xB7
                || (0x300 <= c && c <= 0x036F) || (0x203F <= c && c <= 0x2040)) {
            return true;
        }
        return false;
    }
}

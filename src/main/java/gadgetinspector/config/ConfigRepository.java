package gadgetinspector.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ConfigRepository {
    private static final List<GIConfig> ALL_CONFIGS = Collections.unmodifiableList(Arrays.asList(
            new JavaDeserializationConfig(),
            new JacksonDeserializationConfig(),
            new XstreamDeserializationConfig()));

    public static GIConfig getConfig(String name) {
        for (GIConfig config : ALL_CONFIGS) {
            if (config.getName().equals(name)) {
                return config;
            }
        }
        return null;
    }
}

package gadgetinspector;

import gadgetinspector.config.ConfigRepository;
import gadgetinspector.config.GIConfig;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.PatternLayout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Main entry point for running an end-to-end analysis. Deletes all data files before starting and writes discovered
 * gadget chains to gadget-chains.txt.
 */
public class GadgetInspector {
    private static final Logger LOGGER = LoggerFactory.getLogger(GadgetInspector.class);

    private static void printUsage() {
        System.out.println("Usage:\n  Pass either a single argument which will be interpreted as a WAR, or pass " +
                "any number of arguments which will be intepretted as a list of JARs forming a classpath.");

    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        configureLogging();

        boolean resume = false;
        GIConfig config = ConfigRepository.getConfig("jserial");

        int argIndex = 0;
        while (argIndex < args.length) {
            String arg = args[argIndex];
            if (!arg.startsWith("--")) {
                break;
            }
            if (arg.equals("--resume")) {
                resume = true;
            } else if (arg.equals("--config")) {
                config = ConfigRepository.getConfig(args[++argIndex]);
                if (config == null) {
                    throw new IllegalArgumentException("Invalid config name: " + args[argIndex]);
                }
            } else {
                throw new IllegalArgumentException("Unexpected argument: " + arg);
            }

            argIndex += 1;
        }

        final ClassLoader classLoader;
        if (args.length == argIndex+1 && args[argIndex].toLowerCase().endsWith(".war")) {
            Path path = Paths.get(args[argIndex]);
            LOGGER.info("Using WAR classpath: " + path);
            classLoader = Util.getWarClassLoader(path);
        } else {
            final Path[] jarPaths = new Path[args.length - argIndex];
            for (int i = 0; i < args.length - argIndex; i++) {
                Path path = Paths.get(args[argIndex + i]).toAbsolutePath();
                if (!Files.exists(path)) {
                    throw new IllegalArgumentException("Invalid jar path: " + path);
                }
                jarPaths[i] = path;
            }
            LOGGER.info("Using classpath: " + Arrays.toString(jarPaths));
            classLoader = Util.getJarClassLoader(jarPaths);
        }
        final ClassResourceEnumerator classResourceEnumerator = new ClassResourceEnumerator(classLoader);

        if (!resume) {
            // Delete all existing dat files
            LOGGER.info("Deleting stale data...");
            for (String datFile : Arrays.asList("classes.dat", "methods.dat", "inheritanceMap.dat",
                    "passthrough.dat", "callgraph.dat", "sources.dat", "methodimpl.dat")) {
                final Path path = Paths.get(datFile);
                if (Files.exists(path)) {
                    Files.delete(path);
                }
            }
        }

        // Perform the various discovery steps
        if (!Files.exists(Paths.get("classes.dat")) || !Files.exists(Paths.get("methods.dat"))
                || !Files.exists(Paths.get("inheritanceMap.dat"))) {
            LOGGER.info("Running method discovery...");
            MethodDiscovery methodDiscovery = new MethodDiscovery();
            methodDiscovery.discover(classResourceEnumerator);
            methodDiscovery.save();
        }

        if (!Files.exists(Paths.get("passthrough.dat"))) {
            LOGGER.info("Analyzing methods for passthrough dataflow...");
            PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
            passthroughDiscovery.discover(classResourceEnumerator, config);
            passthroughDiscovery.save();
        }

        if (!Files.exists(Paths.get("callgraph.dat"))) {
            LOGGER.info("Analyzing methods in order to build a call graph...");
            CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
            callGraphDiscovery.discover(classResourceEnumerator, config);
            callGraphDiscovery.save();
        }

        if (!Files.exists(Paths.get("sources.dat"))) {
            LOGGER.info("Discovering gadget chain source methods...");
            SourceDiscovery sourceDiscovery = config.getSourceDiscovery();
            sourceDiscovery.discover();
            sourceDiscovery.save();
        }

        {
            LOGGER.info("Searching call graph for gadget chains...");
            GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery(config);
            gadgetChainDiscovery.discover();
        }

        LOGGER.info("Analysis complete!");
    }

    private static void configureLogging() {
        ConsoleAppender console = new ConsoleAppender();
        String PATTERN = "%d %c [%p] %m%n";
        console.setLayout(new PatternLayout(PATTERN));
        console.setThreshold(Level.DEBUG);
        console.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(console);
    }
}

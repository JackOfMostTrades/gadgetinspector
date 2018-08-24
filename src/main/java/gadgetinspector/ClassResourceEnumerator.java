package gadgetinspector;

import com.google.common.reflect.ClassPath;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collection;

public class ClassResourceEnumerator {
    private final ClassLoader classLoader;

    public ClassResourceEnumerator(ClassLoader classLoader) throws IOException {
        this.classLoader = classLoader;
    }

    public Collection<ClassResource> getAllClasses() throws IOException {
        Collection<ClassResource> result = new ArrayList<>(getRuntimeClasses());
        for (ClassPath.ClassInfo classInfo : ClassPath.from(classLoader).getAllClasses()) {
            result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
        }
        return result;
    }

    private Collection<ClassResource> getRuntimeClasses() throws IOException {
        // A hacky way to get the current JRE's rt.jar. Depending on the class loader, rt.jar may be in the
        // bootstrap classloader so all the JDK classes will be excluded from classpath scanning with this!
        // However, this only works up to Java 8, since after that Java uses some crazy module magic.
        URL stringClassUrl = Object.class.getResource("String.class");
        URLConnection connection = stringClassUrl.openConnection();
        Collection<ClassResource> result = new ArrayList<>();
        if (connection instanceof JarURLConnection) {
            URL runtimeUrl = ((JarURLConnection) connection).getJarFileURL();
            URLClassLoader classLoader = new URLClassLoader(new URL[]{runtimeUrl});

            for (ClassPath.ClassInfo classInfo : ClassPath.from(classLoader).getAllClasses()) {
                result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
            }
            return result;
        }

        // Try finding all the JDK classes using the Java9+ modules method:
        try {
            FileSystem fs = FileSystems.getFileSystem(URI.create("jrt:/"));
            Files.walk(fs.getPath("/")).forEach(p -> {
                if (p.toString().toLowerCase().endsWith(".class")) {
                    result.add(new PathClassResource(p));
                }
            });
        } catch (ProviderNotFoundException e) {
            // Do nothing; this is expected on versions below Java9
        }

        return result;
    }

    public static interface ClassResource {
        public InputStream getInputStream() throws IOException;
        public String getName();
    }

    private static class PathClassResource implements ClassResource {
        private final Path path;

        private PathClassResource(Path path) {
            this.path = path;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return Files.newInputStream(path);
        }

        @Override
        public String getName() {
            return path.toString();
        }
    }

    private static class ClassLoaderClassResource implements ClassResource {
        private final ClassLoader classLoader;
        private final String resourceName;

        private ClassLoaderClassResource(ClassLoader classLoader, String resourceName) {
            this.classLoader = classLoader;
            this.resourceName = resourceName;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return classLoader.getResourceAsStream(resourceName);
        }

        @Override
        public String getName() {
            return resourceName;
        }
    }
}

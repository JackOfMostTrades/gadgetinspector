Gadget Inspector
================

This project inspects Java libraries and classpaths for gadget chains. Gadgets chains are used to construct exploits for deserialization vulnerabilities. By automatically discovering possible gadgets chains in an application's classpath penetration testers can quickly construct exploits and application security engineers can assess the impact of a deserialization vulnerability and prioritize its remediation.

This project was presented at Black Hat USA 2018. Learn more about it there! (Links pending)

DISCLAIMER: This project is alpha at best. It needs tests and documentation added. Feel free to help by adding either!

Building
========

Assuming you have a JDK installed on your system, you should be able to just run `./gradlew shadowJar`. You can then run the application with `java -jar build/libs/gadget-inspector-all.jar <args>`.
 
How to Use
==========

This application expects as argument(s) multiple war or jar files. War files will be exploded and all of its classes and libraries used as a classpath. Usually war files do not contain APIs provided by the application server so those should be added as additional jar files.

Note that the analysis can be memory intensive (and so far gadget inspector has not been optimized at all to be less memory greedy). For small libraries you probably want to allocate at least 2GB of heap size (i.e. with the `-Xmx2G` flag). For larger applications you will want to use as much memory as you can spare.

The toolkit will go through several stages of classpath inspection to build up datasets for use in later stages. These datasets are written to files with a `.dat` extension and can be discarded after your run (they are written mostly so that earlier stages can be skipped during development).

After the analysis has run the file `gadget-chains.txt` will be written.


Example
=======

The following is an example from running against [`commons-collections-3.2.1.jar`](http://central.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar), e.g. with

```
wget http://central.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar
java -Xmx2G -jar build/libs/gadget-inspector-all.jar commons-collections-3.2.1.jar
```

In gadget-chains.txt there is the following chain:
```
com/sun/corba/se/spi/orbutil/proxy/CompositeInvocationHandlerImpl.invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object; (-1)
  com/sun/corba/se/spi/orbutil/proxy/CompositeInvocationHandlerImpl.invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object; (0)
  org/apache/commons/collections/map/DefaultedMap.get(Ljava/lang/Object;)Ljava/lang/Object; (0)
  org/apache/commons/collections/functors/InvokerTransformer.transform(Ljava/lang/Object;)Ljava/lang/Object; (0)
  java/lang/reflect/Method.invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object; (0)
```

The entry point of this chain is an implementation of the JDK `InvocationHandler` class. Using the same trick as in the original commons-collections gadget chain, any serializable implementation of this class is reachable in a gadget chain, so the discovered chain starts here. This method invokes `classToInvocationHandler.get()`. The discovered gadget chain indicates that the `classToInvocationHandler` can be serialized as a `DefaultedMap` so that the this invocation jumps to `DefaultedMap.get()`. The next step in the chain invokes `value.transform()` from this method. The parameter `value` in this class can be serialized as a `InvokerTransformer`. Inside this class's `transform` method we see that we call `cls.getMethodName(iMethodName, ...).invoke(...)`. Gadget inspector determined that `iMethodName` is attacker controllable as a serialized member, and thus an attacker can execute an arbitrary method on the class.
 
This gadget chain is the building block of the [full commons-collections gadget](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java) chain discovered by Frohoff. In the above case, the gadget inspector happened to discovery entry through `CompositeInvocationHandlerImpl` and `DefaultedMap` instead of `AnnotationInvocationHandler` and `LazyMap`, but is largely the same.


Other Examples
==============

If you're looking for more examples of what kind of chains this tool can find, the following libraries also have some interesting results:

* http://central.maven.org/maven2/org/clojure/clojure/1.8.0/clojure-1.8.0.jar
* https://mvnrepository.com/artifact/org.scala-lang/scala-library/2.12.5
* http://central.maven.org/maven2/org/python/jython-standalone/2.5.3/jython-standalone-2.5.3.jar

Don't forget that you can also point gadget inspector at a complete application (packaged as a JAR or WAR). For example, when analyzing the war for the [Zksample2](https://sourceforge.net/projects/zksample2/) application we get the following gadget chain:

```
net/sf/jasperreports/charts/design/JRDesignPieDataset.readObject(Ljava/io/ObjectInputStream;)V (1)
  org/apache/commons/collections/FastArrayList.add(Ljava/lang/Object;)Z (0)
  java/util/ArrayList.clone()Ljava/lang/Object; (0)
  org/jfree/data/KeyToGroupMap.clone()Ljava/lang/Object; (0)
  org/jfree/data/KeyToGroupMap.clone(Ljava/lang/Object;)Ljava/lang/Object; (0)
  java/lang/reflect/Method.invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object; (0)
```

As you can see, this utilizes several different libraries contained in the application in order to build up the chain.

FAQ
===

**Q:** If gadget inspector finds a gadget chain, can an exploit be built from it?

**A:** Not always. The analysis uses some simplifying assumptions and can report false positives (gadget chains that don't actually exist). As a simple example, it doesn't try to solve for the satisfiability of branch conditions. Thus it will report the following as a gadget chain:

```java
public class MySerializableClass implements Serializable {
    public void readObject(ObjectInputStream ois) {
        if (false) System.exit(0);
        ois.defaultReadObject();
    }
}
```

Furthermore, gadget inspector has pretty broad conditions on those functions it considers interesting. For example, it treats reflection as interesting (i.e. calls to `Method.invoke()` where an attacker can control the method), but often times overlooked assertions mean that an attacker can *influence* the method invoked but does not have complete control. For example, an attacker may be able to invoke the "getError()" method in any class, but not any other method name.


**Q:** If no gadget chains were found, does that mean my application is safe from exploitation?

**A:** No! For one, the gadget inspector has a very narrow set of "sink" functions which it considers to have "interesting" side effects. This certainly doesn't mean there aren't other interesting or dangerous behaviors not in the list.

Furthermore, there are a number of limitations to static analysis that mean the gadget inspector will always have blindspots. As an example, gadget inspector would presently miss this because it doesn't follow reflection calls.

```java
public class MySerializableClass implements Serializable {
    public void readObject(ObjectInputStream ois) {
        System.class.getMethod("exit", int.class).invoke(null, 0);
    }
}
```

package com.duminda.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class PropertyResolver {

    static String resourceName = "resources.properties";
    static Properties props;

    static {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        props = new Properties();

        try(InputStream resourceStream = loader.getResourceAsStream(resourceName)) {
            props.load(resourceStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String getPropertyValueByKey(String key){

        /*for (Enumeration<?> e = props.propertyNames(); e.hasMoreElements(); )
            properties.put(e.nextElement().toString(), props.getProperty(e.nextElement().toString()));*/

        return props.getProperty(key);

    }
}

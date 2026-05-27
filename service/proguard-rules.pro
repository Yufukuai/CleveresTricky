# Add project specific ProGuard rules here.

# Keep entry point
-keepclasseswithmembers class cleveres.tricky.cleverestech.MainKt {
    public static void main(java.lang.String[]);
}

# Keep JNI Callbacks (Critical for native binder interception)
-keep class cleveres.tricky.cleverestech.KeystoreInterceptor { *; }
-keep class cleveres.tricky.cleverestech.TelephonyInterceptor { *; }
-keep class cleveres.tricky.cleverestech.PropertyHiderService { *; }
# BinderInterceptor abstract class might be used
-keep class cleveres.tricky.cleverestech.binder.BinderInterceptor { *; }

# Remove all logging (d, i, e, w, v)
-assumenosideeffects class cleveres.tricky.cleverestech.Logger {
    public static void d(...);
    public static void i(...);
    public static void e(...);
    public static void w(...);
    public static void v(...);
}

# Keep BouncyCastle providers
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn javax.naming.**

# Network client java.net.http API on older Android
-dontwarn java.net.http.**

# Aggressive Obfuscation
-repackageclasses 'x'
-allowaccessmodification
-overloadaggressively
-renamesourcefileattribute 'SourceFile'

# Optimization
-optimizationpasses 5
-mergeinterfacesaggressively

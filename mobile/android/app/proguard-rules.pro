# JNA finds its classes, and the structures of the UniFFI bindings, by
# reflection; R8 must keep them as they are.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-keep class dev.sshkeymanager.android.core.** { *; }
-dontwarn java.awt.**

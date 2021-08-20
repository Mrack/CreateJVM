#include <iostream>
#include <cstdlib>
#include "Windows.h"
#include <jni.h>


static char *callJavaMd5(JNIEnv *env, char *pData, int size) {
    jbyte *by = (jbyte *) pData;
    jbyteArray jarray = env->NewByteArray(size);
    env->SetByteArrayRegion(jarray, 0, size, by);
    jclass classMessageDigest = env->FindClass("java/security/MessageDigest");
    jmethodID midGetInstance = env->GetStaticMethodID(classMessageDigest, "getInstance",
                                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jobject objMessageDigest = env->CallStaticObjectMethod(classMessageDigest, midGetInstance,
                                                           env->NewStringUTF("MD5"));
    jmethodID midUpdate = env->GetMethodID(classMessageDigest, "update", "([B)V");
    env->CallVoidMethod(objMessageDigest, midUpdate, jarray);
    jmethodID midDigest = env->GetMethodID(classMessageDigest, "digest", "()[B");
    jbyteArray objArraySign = (jbyteArray) env->CallObjectMethod(objMessageDigest, midDigest);
    jsize intArrayLength = env->GetArrayLength(objArraySign);
    jbyte *byte_array_elements = env->GetByteArrayElements(objArraySign, NULL);
    return reinterpret_cast<char *>(byte_array_elements);
}


char *toHex(char *input, int size) {
    char *res = new char[size * 2 + 1]{0};
    for (int i = 0; i < size; ++i) {
        sprintf(res + i * 2, "%02X", (input[i] + 0xff) % 0xff);
    }
    return res;
}


int main() {
    std::string szJAVAHOME = getenv("JAVA_HOME");
    if (szJAVAHOME.empty()) {
        std::cout << "JAVA_HOME is incorrectly set." << std::endl;
        return -1;
    }
    HMODULE pHinstance = LoadLibrary((szJAVAHOME + R"(\jre\bin\server\jvm.dll)").data());
    jint (*JNI_CreateJavaVM)(JavaVM **pvm, void **penv, void *args);
    JNI_CreateJavaVM = reinterpret_cast<jint (*)(JavaVM **, void **, void *)>
    (GetProcAddress(pHinstance, "JNI_CreateJavaVM"));
    JNIEnv *env;
    JavaVM *jvm;
    JavaVMInitArgs vm_args;
    vm_args.version = JNI_VERSION_1_6;
    vm_args.nOptions = 0;
    vm_args.ignoreUnrecognized = JNI_TRUE;

    long status = JNI_CreateJavaVM(&jvm, (void **) &env, &vm_args);
    if (status == JNI_OK) {
        char *result = callJavaMd5(env, "123", 3);
        std::cout << toHex(result, 16) << std::endl;
    }
    return 0;
}

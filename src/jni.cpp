#include <jni.h>
#include <thread>
#include <iostream>

#include "node.h"


std::map<int, node_t> nodes;

void message_callback(message_t message)
{
    std::cout << "got message: " << message.message << " from: " << message.address.protocol << "://" << message.address.host << ":" << message.address.port << std::endl;
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeStart(JNIEnv *env, jobject obj, jint node_id, jstring identity) {
    const char *str = env->GetStringUTFChars(identity, 0);
    std::string str_identity(str);
    env->ReleaseStringUTFChars(identity, str);

    node_start(&nodes[node_id], str_identity, &message_callback);
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeRun(JNIEnv *env, jobject obj, jint node_id) {
    node_run(&nodes[node_id]);
}

extern "C"
JNIEXPORT jstring
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeAddInterface(JNIEnv *env, jobject obj) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeAddPeer(JNIEnv *env, jobject obj) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeDiscover(JNIEnv *env, jobject obj) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeSendMsg(JNIEnv *env, jobject obj) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeStop(JNIEnv *env, jobject obj, jint node_id) {
    node_stop(&nodes[node_id]);
}

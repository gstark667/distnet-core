#include <jni.h>
#include <thread>
#include <iostream>

#include "node.h"


std::map<int, node_t> nodes;
JNIEnv *genv = NULL;
jobject gobj;

void message_callback(std::string sender, std::string message)
{
    jclass cls = genv->GetObjectClass(gobj);
    jmethodID mid = genv->GetMethodID(cls, "messageCallback", "(Ljava/lang/String;Ljava/lang/String;)V");
    genv->CallVoidMethod(gobj, mid, genv->NewStringUTF(sender.c_str()), genv->NewStringUTF(message.c_str()));

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
    genv = env;
    gobj = obj;
    node_run(&nodes[node_id]);
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeAddInterface(JNIEnv *env, jobject obj, jint node_id, jstring uri) {
    const char *str = env->GetStringUTFChars(uri, 0);
    std::string str_uri(str);
    env->ReleaseStringUTFChars(uri, str);

    node_add_interface(&nodes[node_id], str_uri);
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeAddPeer(JNIEnv *env, jobject obj, jint node_id, jstring uri) {
    const char *str = env->GetStringUTFChars(uri, 0);
    std::string str_uri(str);
    env->ReleaseStringUTFChars(uri, str);

    node_add_peer(&nodes[node_id], str_uri);
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeDiscover(JNIEnv *env, jobject obj, jint node_id, jstring identity) {
    const char *str = env->GetStringUTFChars(identity, 0);
    std::string str_identity(str);
    env->ReleaseStringUTFChars(identity, str);

    node_discover(&nodes[node_id], str_identity);
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeSendMsg(JNIEnv *env, jobject obj, jint node_id, jstring identity, jstring message) {
    std::cout << "sending message from native" << std::endl;
    const char *str = env->GetStringUTFChars(identity, 0);
    std::string str_identity(str);
    env->ReleaseStringUTFChars(identity, str);

    const char *str2 = env->GetStringUTFChars(message, 0);
    std::string str_message(str2);
    env->ReleaseStringUTFChars(message, str2);

    node_send_msg(&nodes[node_id], str_identity, str_message);
}

extern "C"
JNIEXPORT void
JNICALL  Java_com_distnet_gstark31897_distnet_NodeService_nodeStop(JNIEnv *env, jobject obj, jint node_id) {
    node_stop(&nodes[node_id]);
}

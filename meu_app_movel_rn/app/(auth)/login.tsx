// Conteúdo para: meu_app_movel_rn/app/(auth)/login.tsx
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet, ActivityIndicator, Alert, TouchableOpacity, Platform } from 'react-native';
import { useAuth } from '../services/AuthContext'; // Ajuste para subir um nível e depois entrar em services
import { Link } from 'expo-router';

export default function LoginScreen() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { signIn, isLoadingToken } = useAuth();

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) { Alert.alert("Login", "Usuário e senha são obrigatórios."); return; }
    const success = await signIn(username, password);
    // A navegação para (tabs) é tratada pelo RootNavigationDecider em app/_layout.tsx
    if (success) { console.log("LoginScreen: signIn retornou sucesso."); } 
    else { console.log("LoginScreen: signIn retornou falha."); }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Entrar</Text>
      <TextInput style={styles.input} placeholder="Nome de Usuário" value={username} onChangeText={setUsername} autoCapitalize="none" keyboardType="email-address" />
      <TextInput style={styles.input} placeholder="Senha" value={password} onChangeText={setPassword} secureTextEntry />
      {isLoadingToken ? (<ActivityIndicator size="large" color="#007AFF" />) : (<Button title="Entrar" onPress={handleLogin} />)}
      <Link href="/(auth)/register" asChild style={styles.linkContainer}>
        <TouchableOpacity><Text style={styles.linkText}>Não tem uma conta? Registre-se</Text></TouchableOpacity>
      </Link>
    </View>
  );
}
const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', padding: 30, backgroundColor: '#fff' },
  title: { fontSize: 28, fontWeight: 'bold', textAlign: 'center', marginBottom: 40, color: '#333' },
  input: { height: 50, borderColor: '#ccc', borderWidth: 1, marginBottom: 20, paddingHorizontal: 15, borderRadius: 8, backgroundColor: '#f9f9f9', fontSize: 16 },
  linkContainer: { marginTop: 25, alignItems: 'center' },
  linkText: { color: '#007AFF', fontSize: 16 }
});
// Conteúdo CORRIGIDO para: meu_app_movel_rn/app/(tabs)/index.tsx
import React, { useState, useEffect, useCallback } from 'react';
import {
  StyleSheet, Text, View, FlatList, ActivityIndicator,
  TextInput, Button, Alert, Keyboard, TouchableOpacity,
  Image, Platform, SafeAreaView
} from 'react-native';
// Importa o hook de autenticação e a BACKEND_URL do nosso AuthContext
import { useAuth, BACKEND_URL } from '../../contexts/AuthContext'; // Ajuste este caminho se necessário

// Ajuste o caminho da logo. De app/(tabs)/index.tsx para assets na raiz é ../../
const logoPath = '../../assets/images/logo.png'; 

interface Device { id: number; name: string; status: string; }

export default function DeviceControlScreen() {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [newDeviceName, setNewDeviceName] = useState<string>('');
  
  const { userToken, currentUser, signOut } = useAuth();

  const apiFetch = useCallback(async (endpoint: string, options?: RequestInit) => {
    if (!userToken) {
      setError("Não autenticado. Por favor, faça login novamente.");
      // signOut(); // O _layout raiz deve cuidar do redirecionamento se o token sumir
      console.log("apiFetch (DeviceScreen): Token não disponível, abortando requisição.");
      return null;
    }
    const defaultHeaders: HeadersInit = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userToken}`,
    };
    console.log(`Frontend (DeviceScreen): apiFetch chamando: ${BACKEND_URL}${endpoint}`); // Log da URL completa
    try {
      // !!!!! LINHA DO FETCH CORRIGIDA !!!!!
      const response = await fetch(`${BACKEND_URL}${endpoint}`, { ...options, headers: {...defaultHeaders, ...options?.headers} });
      
      if (response.status === 401) {
          Alert.alert("Sessão Expirada", "Sua sessão expirou. Por favor, faça login novamente.");
          await signOut();
          return null;
      }
      if (!response.ok) {
        let eM = `Erro HTTP: ${response.status}`;
        try { const eD = await response.json(); eM = eD.message || eM; } catch (jE) { /* Ignora se corpo do erro não for JSON */ }
        throw new Error(eM);
      }
      if (options?.method === 'DELETE' && (response.status === 200 || response.status === 204)) {
         try { return await response.json(); } catch(e) { return { message: 'Excluído com sucesso' }; }
      }
      return response.json();
    } catch (e: any) {
      console.error(`Frontend (DeviceScreen): Erro em ${options?.method || 'GET'} ${endpoint}:`, e);
      setError(`Falha na operação: ${e.message || 'Erro de rede ou servidor'}`);
      // Não re-throw e; para permitir que o finally do chamador execute sem ser um erro não tratado
      // throw e; 
      return null; // Indica falha
    }
  }, [userToken, signOut]); // BACKEND_URL é constante importada, não precisa ser dep aqui

  const fetchDevices = useCallback(async () => {
    setError(null);
    // console.log(`DeviceScreen: Buscando de: ${BACKEND_URL}/api/devices`); // Log já está em apiFetch
    try {
      const data: Device[] | null = await apiFetch('/api/devices');
      if (data) {
        console.log("DeviceScreen: Dispositivos Recebidos:", data);
        setDevices(data);
        setError(null);
      }
    } catch (e: any) { console.log("DeviceScreen: Erro no fetchDevices (já tratado por apiFetch)"); }
  }, [apiFetch]);

  useEffect(() => {
    if (userToken) {
        const loadInitialDevices = async () => {
            console.log("DeviceScreen: useEffect carga inicial com token...");
            setIsLoading(true);
            await fetchDevices();
            setIsLoading(false);
            console.log("DeviceScreen: useEffect carga inicial OK.");
        };
        loadInitialDevices();
    } else {
        setDevices([]);
        setIsLoading(false);
        // Se não há token, o _layout.tsx raiz deve redirecionar para login.
        // Mas podemos mostrar uma mensagem aqui também se o usuário de alguma forma chegar nesta tela.
        setError("Você não está logado. Por favor, faça login.");
    }
  }, [userToken, fetchDevices]);

  const handleAddDevice = async () => {
    if (!newDeviceName.trim()) { Alert.alert('Erro', 'Nome inválido.'); return; }
    Keyboard.dismiss(); const nameToAdd = newDeviceName; setNewDeviceName('');
    console.log(`DeviceScreen: Add: ${nameToAdd}`); setIsLoading(true); setError(null);
    try {
      const result: Device | null = await apiFetch('/api/add_device', { method: 'POST', body: JSON.stringify({ name: nameToAdd }) });
      if (result) { Alert.alert('Sucesso', `Dispositivo "${result.name}" adicionado!`); await fetchDevices(); }
    } catch (e: any) { /* Erro já tratado por apiFetch */ }
    finally { setIsLoading(false); }
  };

  type ControlAction = 'ON' | 'OFF';
  const handleControlDevice = async (id: number, action: ControlAction) => {
    console.log(`DeviceScreen: Control ID: ${id}, Ação: ${action}`);
    try {
      const result: Device | {message: string} | null = await apiFetch(`/api/device/${id}/control`, { method: 'POST', body: JSON.stringify({ action: action }) });
      if (result && 'id' in result && 'status' in result) {
        Alert.alert('Comando Enviado', `Status: ${result.status}`);
        setDevices(prevDevices => prevDevices.map(d => d.id === id ? { ...d, status: result.status, name: result.name } : d ));
      } else if (result) { Alert.alert('Comando Enviado', (result as {message:string}).message || `Comando ${action} enviado.`); setTimeout(() => fetchDevices(), 300);}
    } catch (e: any) { /* Erro já tratado por apiFetch */ }
  };

  const handleDeleteDevice = (id: number) => {
    Alert.alert( "Confirmar Exclusão", "Tem certeza?",
      [ { text: "Cancelar", style: "cancel" },
        { text: "Excluir", onPress: async () => {
            console.log(`DeviceScreen: Delete ID: ${id}`); setIsLoading(true); setError(null);
            try {
              const result = await apiFetch(`/api/device/${id}`, { method: 'DELETE' });
              if(result) { console.log(`DeviceScreen: ID: ${id} excluído.`); Alert.alert('Sucesso', (result as {message: string}).message || 'Dispositivo excluído.'); await fetchDevices(); }
            } catch (e: any) { /* Erro já tratado por apiFetch */ }
            finally { setIsLoading(false); }
          }, style: "destructive" }
      ], { cancelable: true } );
  };

  const renderDeviceItem = ({ item }: { item: Device }) => (
    <View style={styles.itemContainer}>
      <View style={styles.itemInfo}><Text style={styles.itemText}>{`${item.name} (ID: ${item.id})`}</Text><Text style={styles.itemStatus}>Status: {item.status || 'N/A'}</Text></View>
      <View style={styles.itemButtons}><TouchableOpacity style={[styles.controlButton, styles.buttonOn]} onPress={() => handleControlDevice(item.id, 'ON')}><Text style={styles.buttonText}>ON</Text></TouchableOpacity><TouchableOpacity style={[styles.controlButton, styles.buttonOff]} onPress={() => handleControlDevice(item.id, 'OFF')}><Text style={styles.buttonText}>OFF</Text></TouchableOpacity><Button title="Excluir" color="#ff5c5c" onPress={() => handleDeleteDevice(item.id)} /></View>
    </View>
  );

  let actualLogoSource;
  try { actualLogoSource = require(logoPath); } catch (error) { console.warn(`Logo não encontrada em '${logoPath}'. Verifique o caminho se este arquivo é app/(tabs)/index.tsx e a logo está em MEU_PROJETO/assets/images/logo.png.`); actualLogoSource = null; }

  // O useEffect acima deve lidar com o estado de isLoading para a carga inicial
  // Se userToken for null (ex: após logout), o _layout.tsx raiz deve redirecionar para login.
  // Esta tela só deve ser renderizada se userToken existir.
  if (!userToken && !isLoading) { // isLoading aqui se refere ao isLoading desta tela
      return <View style={styles.center}><Text>Não autenticado. Redirecionando para login...</Text></View>;
  }


  return (
    <SafeAreaView style={styles.safeArea}>
        <View style={styles.container}>
        {actualLogoSource && <Image source={actualLogoSource} style={styles.logo} onError={(e) => console.log("Erro ao carregar logo:", e.nativeEvent.error)} />}
        <Text style={styles.title}>Controle de Dispositivos</Text>
        <View style={styles.headerButtons}>
            {currentUser && <Text style={styles.userInfo}>Usuário: {currentUser.username}</Text>}
            <Button title="Sair" onPress={signOut} color="#888" />
        </View>
        <View style={styles.addDeviceContainer}><TextInput style={styles.input} placeholder="Nome do novo dispositivo" value={newDeviceName} onChangeText={setNewDeviceName} /><Button title="Adicionar Dispositivo" onPress={handleAddDevice} /></View>
        <Text style={styles.listTitle}>Dispositivos:</Text>
        {isLoading && <ActivityIndicator style={styles.loader} size="large" color="#0000ff" />}
        {error && !isLoading && <Text style={styles.errorText}>{error}</Text>}
        {!isLoading && !error && (<FlatList style={styles.list} data={devices} keyExtractor={item => item.id.toString()} renderItem={renderDeviceItem} ListEmptyComponent={<Text>Nenhum dispositivo cadastrado.</Text>} />)}
        </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
    safeArea: { flex: 1, backgroundColor: '#fff' },
    container: { flex: 1, paddingHorizontal: 15, },
    center: { flex: 1, justifyContent: 'center', alignItems: 'center' },
    logo: { width: 80, height: 80, resizeMode: 'contain', alignSelf: 'center', marginBottom: 10, marginTop: Platform.OS === 'android' ? 20 : 10, },
    title: { fontSize: 22, fontWeight: 'bold', marginBottom: 15, textAlign: 'center', },
    headerButtons: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 15, paddingHorizontal: 5 },
    userInfo: { fontSize: 14, color: '#555' },
    addDeviceContainer: { marginBottom: 20, },
    input: { height: 40, borderColor: 'gray', borderWidth: 1, marginBottom: 10, paddingHorizontal: 10, borderRadius: 5, fontSize: 16, },
    listTitle: { fontSize: 18, fontWeight: 'bold', marginBottom: 8, },
    list: { width: '100%', flex: 1, },
    itemContainer: { backgroundColor: '#f0f0f0', paddingVertical: 8, paddingHorizontal: 12, marginBottom: 8, borderRadius: 5, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', },
    itemInfo: { flex: 1, marginRight: 8, },
    itemText: { fontSize: 15, fontWeight: '500' },
    itemStatus: { fontSize: 12, color: '#555'},
    itemButtons: { flexDirection: 'row', alignItems: 'center', },
    controlButton: { paddingVertical: 6, paddingHorizontal: 8, borderRadius: 4, marginHorizontal: 2, minWidth: 35, alignItems: 'center', justifyContent: 'center', },
    buttonOn: { backgroundColor: '#4CAF50', }, buttonOff: { backgroundColor: '#f0ad4e', },
    buttonText: { color: 'white', fontWeight: 'bold', fontSize: 11 },
    errorText: { color: 'red', fontSize: 15, textAlign: 'center', marginTop: 15, },
    loader: { marginTop: 15, }
});
// Conteúdo ATUALIZADO para: meu_app_movel_rn/app/(tabs)/index.tsx
// Inclui botões ON/OFF com estilo dinâmico baseado no status e cores da logo (placeholders)

import React, { useState, useEffect, useCallback } from 'react';
import {
  StyleSheet, Text, View, FlatList, ActivityIndicator,
  TextInput, Button, Alert, Keyboard, TouchableOpacity,
  Image, Platform, SafeAreaView
} from 'react-native';
import { useAuth, BACKEND_URL } from '../../contexts/AuthContext'; // Importa BACKEND_URL do AuthContext

// !!!!! AJUSTE AS CORES DA SUA LOGO AQUI !!!!!
const LOGO_PRIMARY_COLOR = '#0098FF'; // Exemplo: Verde (para ON ou cor principal da logo)
const LOGO_ACCENT_COLOR = '#DD00B3';  // Exemplo: Laranja (para OFF ou cor secundária da logo)
const INACTIVE_BUTTON_COLOR = '#D3D3D3'; // Cinza claro para botões inativos
const INACTIVE_BUTTON_BORDER_COLOR = '#B0B0B0';
// !!!!! FIM DO AJUSTE DE CORES !!!!!

const logoPath = '../../assets/images/logo.png'; 

interface Device { id: number; name: string; status: string; }

export default function DeviceControlScreen() {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [newDeviceName, setNewDeviceName] = useState<string>('');
  
  const { userToken, currentUser, signOut } = useAuth();

  const apiFetch = useCallback(async (endpoint: string, options?: RequestInit) => {
    if (!userToken) { setError("Não autenticado."); /* await signOut(); */ return null; }
    const defaultHeaders: HeadersInit = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${userToken}`};
    console.log(`Frontend (DeviceScreen): apiFetch chamando: ${BACKEND_URL}${endpoint}`);
    try {
      const response = await fetch(`${BACKEND_URL}${endpoint}`, { ...options, headers: {...defaultHeaders, ...options?.headers} });
      if (response.status === 401) { Alert.alert("Sessão Expirada", "Login novamente."); await signOut(); return null; }
      if (!response.ok) { let eM = `Erro HTTP ${response.status}`; try {const eD = await response.json(); eM = eD.message || eM;} catch (jE) {} throw new Error(eM); }
      if (options?.method === 'DELETE' && (response.status === 200 || response.status === 204)) { try { return await response.json(); } catch(e) { return { message: 'Excluído' }; }}
      return response.json();
    } catch (e: any) { console.error(`Frontend (DeviceScreen): Erro em ${options?.method || 'GET'} ${endpoint}:`, e); setError(`Falha: ${e.message || 'Erro rede/servidor'}`); throw e;}
  }, [userToken, signOut]); // BACKEND_URL agora vem do import

  const fetchDevices = useCallback(async () => {
    setError(null);
    try {
      const data: Device[] | null = await apiFetch('/api/devices');
      if (data) { console.log("DeviceScreen: Dispositivos Recebidos:", data); setDevices(data); setError(null); }
    } catch (e: any) { /* já tratado */ }
  }, [apiFetch]);

  useEffect(() => {
    if (userToken) {
        const loadInitialDevices = async () => {
            console.log("DeviceScreen: useEffect carga inicial com token...");
            setIsLoading(true); await fetchDevices(); setIsLoading(false);
            console.log("DeviceScreen: useEffect carga inicial OK.");
        };
        loadInitialDevices();
    } else { setDevices([]); setIsLoading(false); setError("Faça login para ver dispositivos."); }
  }, [userToken, fetchDevices]);

  const handleAddDevice = async () => {
    if (!newDeviceName.trim()) { Alert.alert('Erro', 'Nome inválido.'); return; }
    Keyboard.dismiss(); const nameToAdd = newDeviceName; setNewDeviceName('');
    console.log(`DeviceScreen: Add: ${nameToAdd}`); setIsLoading(true); setError(null);
    try {
      const result: Device | null = await apiFetch('/api/add_device', { method: 'POST', body: JSON.stringify({ name: nameToAdd }) });
      if (result) { Alert.alert('Sucesso', `Dispositivo "${result.name}" adicionado!`); await fetchDevices(); }
    } catch (e: any) { /* já tratado */ } finally { setIsLoading(false); }
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
    } catch (e: any) { /* já tratado */ }
  };

  const handleDeleteDevice = (id: number) => {
    Alert.alert( "Confirmar Exclusão", "Tem certeza?",
      [ { text: "Cancelar", style: "cancel" },
        { text: "Excluir", onPress: async () => {
            console.log(`DeviceScreen: Delete ID: ${id}`); setIsLoading(true); setError(null);
            try {
              const result = await apiFetch(`/api/device/${id}`, { method: 'DELETE' });
              if(result) { console.log(`DeviceScreen: ID: ${id} excluído.`); Alert.alert('Sucesso', (result as {message: string}).message || 'Excluído.'); await fetchDevices(); }
            } catch (e: any) { /* já tratado */ } finally { setIsLoading(false); }
          }, style: "destructive" }
      ], { cancelable: true } );
  };

  // --- Função para renderizar cada item da lista (COM BOTÕES DE CONTROLE ESTILIZADOS) ---
  const renderDeviceItem = ({ item }: { item: Device }) => {
    const isDeviceOn = item.status === 'ON';

    return (
      <View style={styles.itemContainer}>
        <View style={styles.itemInfo}>
          <Text style={styles.itemText}>{`${item.name} (ID: ${item.id})`}</Text>
          <Text style={isDeviceOn ? styles.itemStatusOn : styles.itemStatusOff}>
            Status: {item.status || 'N/A'}
          </Text>
        </View>
        <View style={styles.itemButtons}>
          <TouchableOpacity
            style={[
              styles.controlButton,
              isDeviceOn ? styles.buttonOnActive : styles.buttonOnInactive,
            ]}
            onPress={() => handleControlDevice(item.id, 'ON')}
            disabled={isDeviceOn}
          >
            <Text style={styles.buttonText}>ON</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[
              styles.controlButton,
              !isDeviceOn ? styles.buttonOffActive : styles.buttonOffInactive,
            ]}
            onPress={() => handleControlDevice(item.id, 'OFF')}
            disabled={!isDeviceOn}
          >
            <Text style={styles.buttonText}>OFF</Text>
          </TouchableOpacity>
          <Button
            title="Excluir"
            color="#e74c3c" // Um vermelho um pouco diferente
            onPress={() => handleDeleteDevice(item.id)}
          />
        </View>
      </View>
    );
  };

  let actualLogoSource;
  try { actualLogoSource = require(logoPath); } catch (error) { console.warn(`Logo não encontrada em '${logoPath}'.`); actualLogoSource = null; }

  return (
    <SafeAreaView style={styles.safeArea}>
      <View style={styles.container}>
        {actualLogoSource && <Image source={actualLogoSource} style={styles.logo} />}
        <Text style={styles.title}>Controle de Dispositivos</Text>
        <View style={styles.headerButtons}>
          {currentUser && <Text style={styles.userInfo}>Usuário: {currentUser.username}</Text>}
          <Button title="Sair" onPress={signOut} color="#888" />
        </View>
        <View style={styles.addDeviceContainer}>
          <TextInput style={styles.input} placeholder="Nome do novo dispositivo" value={newDeviceName} onChangeText={setNewDeviceName} />
          <Button title="Adicionar Dispositivo" onPress={handleAddDevice} />
        </View>
        <Text style={styles.listTitle}>Dispositivos:</Text>
        {isLoading && <ActivityIndicator style={styles.loader} size="large" color="#0000ff" />}
        {error && !isLoading && <Text style={styles.errorText}>{error}</Text>}
        {!isLoading && !error && (
          <FlatList style={styles.list} data={devices} keyExtractor={item => item.id.toString()} renderItem={renderDeviceItem} ListEmptyComponent={<Text>Nenhum dispositivo cadastrado.</Text>} />
        )}
      </View>
    </SafeAreaView>
  );
}

// Estilos (COM NOVOS ESTILOS PARA BOTÕES ON/OFF E STATUS)
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
    itemContainer: { backgroundColor: '#f0f0f0', paddingVertical: 10, paddingHorizontal: 15, marginBottom: 8, borderRadius: 5, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', },
    itemInfo: { flex: 1, marginRight: 8, },
    itemText: { fontSize: 15, fontWeight: '500' },
    itemStatus: { fontSize: 12, color: '#555'}, // Estilo base para status
    itemStatusOn: { fontSize: 12, color: LOGO_PRIMARY_COLOR, fontWeight: 'bold' }, // <<< NOVO
    itemStatusOff: { fontSize: 12, color: LOGO_ACCENT_COLOR, fontWeight: 'bold' }, // <<< NOVO (ou um cinza)
    itemButtons: { flexDirection: 'row', alignItems: 'center', },
    controlButton: { paddingVertical: 6, paddingHorizontal: 12, borderRadius: 5, marginHorizontal: 3, minWidth: 45, alignItems: 'center', justifyContent: 'center', borderWidth: 1, },
    buttonOnActive: { backgroundColor: LOGO_PRIMARY_COLOR, borderColor: LOGO_PRIMARY_COLOR },     // <<< USA COR DA LOGO
    buttonOnInactive: { backgroundColor: '#e9f5e9', borderColor: INACTIVE_BUTTON_BORDER_COLOR }, // <<< Um tom mais claro ou cinza
    buttonOffActive: { backgroundColor: LOGO_ACCENT_COLOR, borderColor: LOGO_ACCENT_COLOR },   // <<< USA COR DA LOGO
    buttonOffInactive: { backgroundColor: '#fdeee1', borderColor: INACTIVE_BUTTON_BORDER_COLOR },// <<< Um tom mais claro ou cinza
    buttonText: { color: 'white', fontWeight: 'bold', fontSize: 11 },
    errorText: { color: 'red', fontSize: 15, textAlign: 'center', marginTop: 15, },
    loader: { marginTop: 15, }
});
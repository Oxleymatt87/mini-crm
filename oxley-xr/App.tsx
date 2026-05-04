/**
 * Oxley XR — WebView wrapper with bottom tab navigation.
 */

import React from 'react';
import { StatusBar, StyleSheet, Text, View } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { NavigationContainer } from '@react-navigation/native';
import {
  createBottomTabNavigator,
  BottomTabNavigationOptions,
} from '@react-navigation/bottom-tabs';
import { WebView } from 'react-native-webview';

const URLS = {
  Map: 'https://inventory-setup-b3f20.web.app/map-xr.html',
  Customers: 'https://inventory-setup-b3f20.web.app/customers.html',
  Ledger: 'https://inventory-setup-b3f20.web.app/ledger.html',
  Inventory: 'https://inventory-setup-b3f20.web.app/intake.html',
  Dashboard: 'https://inventory-setup-b3f20.web.app/index.html',
} as const;

type TabName = keyof typeof URLS;

const TAB_ICONS: Record<TabName, string> = {
  Map: '🗺',
  Customers: '👥',
  Ledger: '📒',
  Inventory: '📦',
  Dashboard: '📊',
};

function makeWebViewScreen(url: string) {
  return function WebViewScreen() {
    return (
      <View style={styles.flex}>
        <WebView
          source={{ uri: url }}
          style={styles.flex}
          javaScriptEnabled
          domStorageEnabled
          allowsInlineMediaPlayback
          mediaPlaybackRequiresUserAction={false}
          originWhitelist={['*']}
          startInLoadingState
        />
      </View>
    );
  };
}

const Tab = createBottomTabNavigator();

const screenOptions = ({
  route,
}: {
  route: { name: string };
}): BottomTabNavigationOptions => ({
  headerShown: false,
  tabBarActiveTintColor: '#ffffff',
  tabBarInactiveTintColor: '#888888',
  tabBarStyle: styles.tabBar,
  tabBarLabelStyle: styles.tabLabel,
  tabBarIcon: ({ color }) => (
    <Text style={[styles.tabIcon, { color }]}>
      {TAB_ICONS[route.name as TabName] ?? '•'}
    </Text>
  ),
});

function App() {
  return (
    <SafeAreaProvider>
      <StatusBar hidden />
      <NavigationContainer>
        <Tab.Navigator initialRouteName="Map" screenOptions={screenOptions}>
          <Tab.Screen name="Map" component={makeWebViewScreen(URLS.Map)} />
          <Tab.Screen
            name="Customers"
            component={makeWebViewScreen(URLS.Customers)}
          />
          <Tab.Screen
            name="Ledger"
            component={makeWebViewScreen(URLS.Ledger)}
          />
          <Tab.Screen
            name="Inventory"
            component={makeWebViewScreen(URLS.Inventory)}
          />
          <Tab.Screen
            name="Dashboard"
            component={makeWebViewScreen(URLS.Dashboard)}
          />
        </Tab.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: '#1a1a1a' },
  tabBar: {
    backgroundColor: '#1a1a1a',
    borderTopColor: '#1a1a1a',
  },
  tabLabel: {
    fontSize: 11,
  },
  tabIcon: {
    fontSize: 20,
  },
});

export default App;

/**
 * Oxley XR — WebView wrapper with bottom tab navigation.
 * Debug colors are intentionally loud so we can confirm what renders.
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

function makeWebViewScreen(url: string, label: string) {
  return function WebViewScreen() {
    return (
      <View style={styles.flex}>
        <View style={styles.debugBanner}>
          <Text style={styles.debugBannerText}>{label} · {url}</Text>
        </View>
        <WebView
          source={{ uri: url }}
          style={styles.flex}
          javaScriptEnabled
          domStorageEnabled
          allowsInlineMediaPlayback
          mediaPlaybackRequiresUserAction={false}
          originWhitelist={['*']}
          startInLoadingState
          onError={(e) =>
            console.warn('WebView error', label, e.nativeEvent)
          }
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
  tabBarInactiveTintColor: '#cccccc',
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
      <View style={styles.outerDebug}>
        <NavigationContainer>
          <Tab.Navigator initialRouteName="Map" screenOptions={screenOptions}>
            <Tab.Screen
              name="Map"
              component={makeWebViewScreen(URLS.Map, 'MAP')}
            />
            <Tab.Screen
              name="Customers"
              component={makeWebViewScreen(URLS.Customers, 'CUSTOMERS')}
            />
            <Tab.Screen
              name="Ledger"
              component={makeWebViewScreen(URLS.Ledger, 'LEDGER')}
            />
            <Tab.Screen
              name="Inventory"
              component={makeWebViewScreen(URLS.Inventory, 'INVENTORY')}
            />
            <Tab.Screen
              name="Dashboard"
              component={makeWebViewScreen(URLS.Dashboard, 'DASHBOARD')}
            />
          </Tab.Navigator>
        </NavigationContainer>
      </View>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  // Loud red border so we can see if the React tree mounts at all.
  outerDebug: {
    flex: 1,
    backgroundColor: '#000000',
    borderColor: '#ff0080',
    borderWidth: 4,
  },
  flex: { flex: 1, backgroundColor: '#1a1a1a' },
  debugBanner: {
    backgroundColor: '#ff0080',
    paddingVertical: 6,
    paddingHorizontal: 12,
  },
  debugBannerText: {
    color: '#ffffff',
    fontSize: 12,
    fontWeight: '700',
  },
  tabBar: {
    backgroundColor: '#005f9e',
    borderTopColor: '#00aaff',
    borderTopWidth: 2,
    height: 64,
  },
  tabLabel: {
    fontSize: 11,
    fontWeight: '600',
  },
  tabIcon: {
    fontSize: 22,
  },
});

export default App;


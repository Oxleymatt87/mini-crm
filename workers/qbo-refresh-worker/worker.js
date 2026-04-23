export default {
  async fetch(request, env, ctx) {
    // Add CORS headers for browser requests
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    
    try {
      // Route handling
      if (url.pathname === '/api/invoices' || url.pathname === '/invoices') {
        const invoices = await getInvoices(env);
        return new Response(JSON.stringify(invoices), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      if (url.pathname === '/api/customers' || url.pathname === '/customers') {
        const customers = await getCustomers(env);
        return new Response(JSON.stringify(customers), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (url.pathname === '/api/items' || url.pathname === '/items') {
        const items = await getItems(env);
        return new Response(JSON.stringify(items), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (url.pathname === '/debug') {
        return new Response(JSON.stringify({
          message: 'Worker is working!',
          timestamp: new Date().toISOString(),
          hasSecrets: {
            realmId: !!env.QBO_REALM_ID,
            clientId: !!env.QBO_CLIENT_ID,
            accessToken: !!env.QBO_ACCESS_TOKEN
          }
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Default route
      return new Response(JSON.stringify({
        message: 'QuickBooks API Worker',
        endpoints: [
          '/api/invoices - Get all invoices',
          '/api/customers - Get all customers', 
          '/api/items - Get all items',
          '/debug - Check worker status'
        ]
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
      return new Response(JSON.stringify({
        error: error.message,
        stack: error.stack
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};

// Function to refresh access token if needed
async function refreshAccessToken(env) {
  const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${btoa(env.QBO_CLIENT_ID + ':' + env.QBO_CLIENT_SECRET)}`
    },
    body: new URLSearchParams({
      'grant_type': 'refresh_token',
      'refresh_token': env.QBO_REFRESH_TOKEN
    })
  });

  if (!response.ok) {
    throw new Error(`Token refresh failed: ${response.status} ${response.statusText}`);
  }

  return await response.json();
}

// Function to make authenticated QuickBooks API calls
async function makeQBORequest(endpoint, env) {
  const baseURL = 'https://sandbox-quickbooks.api.intuit.com'; // Use https://quickbooks.api.intuit.com for production
  const url = `${baseURL}/v3/company/${env.QBO_REALM_ID}/${endpoint}`;
  
  let accessToken = env.QBO_ACCESS_TOKEN;
  
  // Try request with current token
  let response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json'
    }
  });

  // If unauthorized, try refreshing token
  if (response.status === 401) {
    const tokenData = await refreshAccessToken(env);
    accessToken = tokenData.access_token;
    
    // Retry with new token
    response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });
  }

  if (!response.ok) {
    throw new Error(`QBO API error: ${response.status} ${response.statusText}`);
  }

  return await response.json();
}

// Get all invoices
async function getInvoices(env) {
  try {
    const data = await makeQBORequest("invoices?maxresults=100", env);
    
    if (!data.QueryResponse || !data.QueryResponse.Invoice) {
      return {
        invoices: [],
        totalSales: 0,
        count: 0,
        period: 'All time'
      };
    }

    const invoices = data.QueryResponse.Invoice.map(invoice => ({
      id: invoice.Id,
      docNumber: invoice.DocNumber || 'N/A',
      customer: invoice.CustomerRef?.name || 'Unknown',
      customerId: invoice.CustomerRef?.value,
      amount: parseFloat(invoice.TotalAmt || 0),
      date: invoice.TxnDate,
      dueDate: invoice.DueDate,
      status: invoice.Balance && parseFloat(invoice.Balance) > 0 ? 'Open' : 'Paid',
      balance: parseFloat(invoice.Balance || 0)
    }));

    const totalSales = invoices.reduce((sum, inv) => sum + inv.amount, 0);

    return {
      invoices: invoices,
      totalSales: totalSales,
      count: invoices.length,
      period: 'All time',
      lastUpdated: new Date().toISOString()
    };
  } catch (error) {
    throw new Error(`Failed to fetch invoices: ${error.message}`);
  }
}

// Get all customers
async function getCustomers(env) {
  try {
    const data = await makeQBORequest("customers?maxresults=100", env);
    
    if (!data.QueryResponse || !data.QueryResponse.Customer) {
      return { customers: [], count: 0 };
    }

    const customers = data.QueryResponse.Customer.map(customer => ({
      id: customer.Id,
      name: customer.Name,
      displayName: customer.DisplayName || customer.Name,
      email: customer.PrimaryEmailAddr?.Address,
      phone: customer.PrimaryPhone?.FreeFormNumber,
      active: customer.Active !== false
    }));

    return {
      customers: customers,
      count: customers.length
    };
  } catch (error) {
    throw new Error(`Failed to fetch customers: ${error.message}`);
  }
}

// Get all items
async function getItems(env) {
  try {
    const data = await makeQBORequest("items?maxresults=100", env);
    
    if (!data.QueryResponse || !data.QueryResponse.Item) {
      return { items: [], count: 0 };
    }

    const items = data.QueryResponse.Item.map(item => ({
      id: item.Id,
      name: item.Name,
      type: item.Type,
      description: item.Description,
      unitPrice: parseFloat(item.UnitPrice || 0),
      active: item.Active !== false
    }));

    return {
      items: items,
      count: items.length
    };
  } catch (error) {
    throw new Error(`Failed to fetch items: ${error.message}`);
  }
}

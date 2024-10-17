let opaWasmModule;

// Load OPA WebAssembly and handle imports correctly
fetch('opa.wasm')  // Ensure this path points to your actual .wasm file
  .then(response => response.arrayBuffer())
  .then(buffer => {
    // Provide the necessary imports object to instantiate the WebAssembly module
    const imports = {
      env: {
        memory: new WebAssembly.Memory({ initial: 256 }),
        __indirect_function_table: new WebAssembly.Table({ initial: 0, element: 'anyfunc' }),

        // Placeholder built-in functions, replace with actual logic if needed
        opa_builtin0: function() {
          console.log('opa_builtin0 called');
          return 0;
        },
        opa_builtin1: function() {
          console.log('opa_builtin1 called');
          return 0;
        },
        opa_builtin2: function() {
          console.log('opa_builtin2 called');
          return 0;
        },
        opa_builtin3: function() {
          console.log('opa_builtin3 called');
          return 0;
        },
        opa_builtin4: function() {
          console.log('opa_builtin4 called');
          return 0;
        },
        opa_builtin5: function() {
          console.log('opa_builtin5 called');
          return 0;
        },
        opa_abort: function() {
          console.log('opa_abort called');
          return 0; // Placeholder return value
        },
      }
    };
    
    // Instantiate the WebAssembly module with the provided imports
    return WebAssembly.instantiate(buffer, imports);
  })
  .then(result => {
    opaWasmModule = result.instance;
    console.log("OPA WebAssembly Module loaded successfully");
  })
  .catch(error => {
    console.error("Error loading OPA WebAssembly module:", error);
  });

// Run policy when the button is clicked
document.getElementById('run-policy').addEventListener('click', () => {
  const jwtInput = document.getElementById('jwt-input').value;
  const regoPolicy = document.getElementById('rego-input').value;

  if (!jwtInput || !opaWasmModule) {
    alert('Please enter a valid JWT and ensure the OPA module is loaded.');
    return;
  }

  try {
    // Parse the JWT (assuming it's in the standard format)
    const jwtPayload = jwtInput;
    const claims = JSON.parse(jwtPayload);
    
    // Evaluate the claims using the Rego policy
    const evaluationResult = evaluateRegoPolicy(claims, regoPolicy);

    // Update colors based on evaluation result (this function needs to be defined)
    updateClaimColors(claims, evaluationResult);

  } catch (e) {
    console.error('Error parsing JWT or evaluating policy:', e);
  }
});

function evaluateRegoPolicy(claims, regoPolicy) {
    if (!opaWasmModule) {
      console.error("OPA WebAssembly module not loaded.");
      return {};
    }
  
    try {
      // Prepare the input for OPA
      const input = JSON.stringify(claims);
      console.log("Input to WebAssembly:", input);
  
      // Reset OPA memory and initialize the heap
      opaWasmModule.exports.opa_heap_ptr_set(0);  // Reset OPA heap
      const heapStart = opaWasmModule.exports.opa_heap_ptr_get(); // Get heap pointer
      
      // Write the input (claims) into the OPA memory
      const inputAddr = writeToWasmMemory(input, opaWasmModule.exports);
  
      // Call the OPA evaluation function
      const evalAddr = opaWasmModule.exports.opa_eval(inputAddr);
  
      // Read the result from WebAssembly memory
      const result = readFromWasmMemory(evalAddr, opaWasmModule.exports);
  
      return JSON.parse(result); // Return the evaluation result as JSON
    } catch (error) {
      console.error("Error evaluating the policy:", error);
    }
  }
  
  

  function writeToWasmMemory(data, exports) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    const pointer = exports.opa_malloc(encodedData.length);
  
    const memory = new Uint8Array(exports.memory.buffer, pointer, encodedData.length);
    memory.set(encodedData);
  
    return pointer;
  }
  
  function readFromWasmMemory(pointer, exports) {
    const decoder = new TextDecoder();
    const memory = new Uint8Array(exports.memory.buffer, pointer);
    let resultString = '';
  
    // Reading byte by byte until null terminator (0) is found
    for (let i = pointer; memory[i] !== 0; i++) {
      resultString += decoder.decode(memory.subarray(i, i + 1));
    }
  
    return resultString;
  }
  

function updateClaimColors(claims, evaluationResult) {
  const claimsPre = document.getElementById('jwt-claims');
  claimsPre.innerHTML = ''; // Clear existing content

  // Loop through claims and apply colors based on evaluation
  Object.keys(claims).forEach(claim => {
    const value = claims[claim];
    let claimColor = evaluationResult[claim] ? 'green' : 'red'; // Based on eval result

    claimsPre.innerHTML += `<span style="color: ${claimColor};">"${claim}": ${JSON.stringify(value)}</span>\n`;
  });
}

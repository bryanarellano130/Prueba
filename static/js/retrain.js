document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('retrain-form');
    const statusDiv = document.getElementById('retrain-status');
    const submitButton = document.getElementById('retrain-button');
    const loadingSpinner = document.getElementById('loading-spinner');
    const fileInput = document.getElementById('newdata');

    if (!form || !statusDiv || !submitButton || !loadingSpinner || !fileInput) {
        console.error("Error: No se encontraron todos los elementos del formulario en el DOM.");
        if(statusDiv) statusDiv.innerHTML = '<div class="alert alert-danger">Error interno de la página (elementos no encontrados).</div>';
        return; // Detener si falta algo esencial
    }

    form.addEventListener('submit', function(event) {
        event.preventDefault(); // Prevenir el envío normal

        // Validar que se haya seleccionado un archivo
        if (fileInput.files.length === 0) {
            statusDiv.innerHTML = '<div class="alert alert-warning">Por favor, seleccione un archivo CSV.</div>';
            statusDiv.className = 'alert alert-warning';
            return;
        }

        const formData = new FormData(form);

        // Mostrar indicador de carga y deshabilitar botón
        statusDiv.innerHTML = '<div class="alert alert-info">Iniciando reentrenamiento... Esto puede tardar varios minutos. Por favor, espere.</div>';
        statusDiv.className = 'alert alert-info'; // Limpiar clases previas
        submitButton.disabled = true;
        loadingSpinner.style.display = 'inline-block'; // Mostrar spinner

        // Enviar la solicitud al backend (ruta /retrain definida en Flask)
        fetch('/retrain_model', { // Use the correct Flask route
        method: 'POST',
            body: formData
        })
        .then(response => {
            // Intentar obtener el JSON incluso si la respuesta no es ok (puede contener error)
            return response.json().then(data => ({ status: response.status, body: data }));
        })
        .then(({ status, body }) => {
            if (status >= 200 && status < 300 && body.success) {
                // Éxito
                statusDiv.innerHTML = `<div class="alert alert-success"><strong>Éxito:</strong> ${body.message || 'Modelo reentrenado correctamente.'}</div>`;
                statusDiv.className = 'alert alert-success';
                 // Limpiar el input de archivo después de éxito (opcional)
                fileInput.value = ''; 
            } else {
                // Error (del backend o respuesta no exitosa)
                let errorMessage = 'Ocurrió un error.';
                if (body && body.error) {
                    errorMessage = body.error;
                } else if (status === 400) {
                     errorMessage = body.error || "Solicitud incorrecta (ej: archivo no válido o faltante)."
                } else if (status === 413) {
                     errorMessage = "El archivo es demasiado grande. El límite es 16MB."
                } else if (status === 500) {
                    errorMessage = body.error || "Error interno en el servidor durante el reentrenamiento."
                }
                console.error('Error en reentrenamiento:', status, body);
                statusDiv.innerHTML = `<div class="alert alert-danger"><strong>Error:</strong> ${errorMessage}</div>`;
                statusDiv.className = 'alert alert-danger';
            }
        })
        .catch(error => {
            // Error de red o al procesar la respuesta
            console.error('Error en fetch:', error);
            statusDiv.innerHTML = `<div class="alert alert-danger"><strong>Error de conexión:</strong> No se pudo conectar con el servidor. ${error.message || ''}</div>`;
            statusDiv.className = 'alert alert-danger';
        })
        .finally(() => {
            // Siempre se ejecuta: Habilitar botón y ocultar spinner
            submitButton.disabled = false;
            loadingSpinner.style.display = 'none';
        });
    });
});
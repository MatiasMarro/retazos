/* Sobrantes del taller: la página de los recortes guardados (decisión 0049).

   Lee sobrantes.json (lo arma `uv run taller sobrantes pagina` con catalogos/sobrantes.yaml) y guarda cada dato en su
   propio arreglo (Int32Array, Float64Array…), uno por columna. Para ordenar arma una permutación por clave una sola vez
   y la guarda; cada búsqueda o filtro es una sola pasada por esa permutación, sin volver a ordenar. La tabla dibuja solo
   las filas que se ven y el gráfico va en un canvas, con los puntos de fondo dibujados una vez por tamaño de pantalla.
   Así anda igual con diez recortes que con cien mil. Sin librerías. */
(() => {
  "use strict";

  const UM_POR_MM = 1000;
  const MM2_POR_M2 = 1e6;
  const DIA_MS = 86400000;
  const EJEMPLO_POR_DEFECTO = 48;
  const EJEMPLO_MAXIMO = 200000;
  const BARRAS = 8;
  const MUCHOS_PUNTOS = 4000;
  const CERCA_PX = 12;
  const DIBUJO_MAXIMO_DE_PIEZAS = 400;
  const NOMBRE_VETA = ["Sin veta", "Veta a lo largo", "Veta a lo ancho"];
  const CORTO_VETA = ["Sin veta", "A lo largo", "A lo ancho"];

  const mmF = new Intl.NumberFormat("es-AR", { maximumFractionDigits: 1, useGrouping: false });
  const m2F = new Intl.NumberFormat("es-AR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const nF = new Intl.NumberFormat("es-AR");
  const $ = (id) => document.getElementById(id);
  const mm = (v) => mmF.format(v);
  const medida = (l, a) => `${mm(l)} × ${mm(a)}`;
  const metros2 = (mm2) => `${m2F.format(mm2 / MM2_POR_M2)} m²`;
  const dos = (n) => String(n).padStart(2, "0");
  const fechaTexto = (dias) => {
    const d = new Date(dias * DIA_MS);
    return `${dos(d.getUTCDate())}-${dos(d.getUTCMonth() + 1)}-${d.getUTCFullYear()}`;
  };
  const normalizar = (t) =>
    String(t)
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .toLowerCase();
  const escapar = (t) =>
    String(t).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const numeroDe = (input) => {
    const v = parseFloat(String(input.value).replace(",", "."));
    return Number.isFinite(v) && v > 0 ? v : 0;
  };

  const D = {}; // los datos, por columnas
  const F = {
    // lo que se busca
    tokens: [],
    numero: -1,
    largo: 0,
    ancho: 0,
    margen: 0,
    separacion: 0,
    respetarVeta: true,
    veta: "todas",
    espesores: new Set(),
    placas: new Set(),
  };
  const V = { clave: "area", desc: true, cuantos: 0, elegido: -1, fila: 48 }; // la vista

  // ----------------------------------------------------------------------------------------------- arrancar

  function mostrarError(texto) {
    $("cargando").hidden = true;
    $("entrada").hidden = true;
    $("error").hidden = false;
    $("error").textContent = texto;
    $("estado").textContent = "Sin datos";
  }

  async function iniciar() {
    configurarTema();
    $("salir").addEventListener("click", () => {
      olvidarLaLlave();
      location.reload();
    });
    const pedido = new URLSearchParams(location.search).get("ejemplo");
    let datos;
    try {
      const respuesta = await fetch("sobrantes.json", { cache: "no-cache" });
      if (!respuesta.ok) throw new Error(`HTTP ${respuesta.status}`);
      datos = await respuesta.json();
    } catch (error) {
      mostrarError(
        "No pude leer la lista de recortes (sobrantes.json). Abrí la página publicada, o armala con «uv run taller sobrantes pagina».",
      );
      return;
    }
    if (datos.formato === FORMATO_CERRADO) {
      datos = await abrirConLaClave(datos);
      if (!datos) return;
      $("salir").hidden = false;
    }
    if (datos.formato !== "sobrantes-1") {
      mostrarError("La lista de recortes viene en un formato que esta página no conoce. Volvé a cargarla en un rato.");
      return;
    }
    let ejemplo = 0;
    if (pedido !== null) {
      ejemplo = Math.min(EJEMPLO_MAXIMO, Math.max(1, parseInt(pedido, 10) || EJEMPLO_POR_DEFECTO));
    } else if (datos.sobrantes.numero.length === 0) {
      ejemplo = EJEMPLO_POR_DEFECTO;
    }
    const reales = datos.sobrantes.numero.length;
    if (ejemplo) datos = conEjemplo(datos, ejemplo);
    preparar(datos, ejemplo, reales);
  }

  // ----------------------------------------------------------------------------------------------- el candado

  /* La lista publicada viene cerrada con la contraseña del dueño (AES-256-GCM, con la llave sacada de la contraseña con
     PBKDF2-SHA256: decisión 0050). Se abre acá, con WebCrypto; la contraseña no sale del navegador. Con «recordarme»,
     lo que queda guardado es la llave (no la contraseña), y solo en este equipo. */
  const FORMATO_CERRADO = "sobrantes-cifrado-1";
  const LLAVE_GUARDADA = "sobrantes-llave";
  const texto = new TextEncoder();

  function deBase64(t) {
    const binario = atob(t);
    const bytes = new Uint8Array(binario.length);
    for (let i = 0; i < binario.length; i++) bytes[i] = binario.charCodeAt(i);
    return bytes;
  }

  function aBase64(buffer) {
    let binario = "";
    for (const b of new Uint8Array(buffer)) binario += String.fromCharCode(b);
    return btoa(binario);
  }

  async function llaveDeLaClave(clave, cerrado) {
    const base = await crypto.subtle.importKey("raw", texto.encode(clave.trim().normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: deBase64(cerrado.sal), iterations: cerrado.iteraciones, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      true,
      ["decrypt"],
    );
  }

  async function abrir(cerrado, llave) {
    const abierto = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: deBase64(cerrado.iv), additionalData: texto.encode(cerrado.formato) },
      llave,
      deBase64(cerrado.datos),
    );
    return JSON.parse(new TextDecoder().decode(abierto));
  }

  function llaveGuardada() {
    try {
      return localStorage.getItem(LLAVE_GUARDADA) || sessionStorage.getItem(LLAVE_GUARDADA);
    } catch (error) {
      return null;
    }
  }

  function guardarLaLlave(cruda, recordar) {
    try {
      (recordar ? localStorage : sessionStorage).setItem(LLAVE_GUARDADA, aBase64(cruda));
    } catch (error) {
      /* sin almacenamiento: la contraseña se pide cada vez */
    }
  }

  function olvidarLaLlave() {
    try {
      localStorage.removeItem(LLAVE_GUARDADA);
      sessionStorage.removeItem(LLAVE_GUARDADA);
    } catch (error) {
      /* nada guardado */
    }
  }

  /* La lista abierta: con la llave guardada si todavía sirve; si no, con la contraseña que se escribe en la entrada. */
  async function abrirConLaClave(cerrado) {
    if (!(window.crypto && crypto.subtle)) {
      mostrarError("Este navegador no puede abrir la lista. Probá con uno más nuevo: Chrome, Edge, Firefox o Safari.");
      return null;
    }
    const guardada = llaveGuardada();
    if (guardada) {
      try {
        const llave = await crypto.subtle.importKey("raw", deBase64(guardada), { name: "AES-GCM" }, false, ["decrypt"]);
        return await abrir(cerrado, llave);
      } catch (error) {
        olvidarLaLlave(); // cambió la contraseña: se vuelve a pedir
      }
    }
    $("cargando").hidden = true;
    $("entrada").hidden = false;
    $("estado").textContent = "Lista cerrada";
    const clave = $("clave");
    const ver = $("ver-clave");
    ver.addEventListener("click", () => {
      const mostrar = clave.type === "password";
      clave.type = mostrar ? "text" : "password";
      ver.textContent = mostrar ? "Ocultar" : "Mostrar";
      ver.setAttribute("aria-pressed", String(mostrar));
      clave.focus();
    });
    clave.focus();
    return new Promise((listo) => {
      $("entrada-form").addEventListener("submit", async (evento) => {
        evento.preventDefault();
        const boton = $("entrar");
        $("entrada-error").hidden = true;
        boton.disabled = true;
        boton.textContent = "Abriendo la lista…";
        try {
          const llave = await llaveDeLaClave(clave.value, cerrado);
          const abiertos = await abrir(cerrado, llave);
          guardarLaLlave(await crypto.subtle.exportKey("raw", llave), $("recordar").checked);
          clave.value = "";
          $("entrada").hidden = true;
          $("cargando").hidden = false;
          listo(abiertos);
        } catch (error) {
          $("entrada-error").hidden = false;
          clave.select();
        } finally {
          boton.disabled = false;
          boton.textContent = "Entrar";
        }
      });
    });
  }

  // ----------------------------------------------------------------------------------------------- el ejemplo

  function azar(semilla) {
    let a = semilla >>> 0;
    return () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  /* Recortes inventados (siempre los mismos) para ver la página cuando todavía no hay ninguno guardado, o con
     ?ejemplo=100000 para probarla con muchos. Se marcan como ejemplo en toda la página. */
  function conEjemplo(datos, cantidad) {
    const placas =
      datos.placas_de_ejemplo && datos.placas_de_ejemplo.length
        ? datos.placas_de_ejemplo
        : [{ id: "ejemplo", nombre: "Melamina blanca 18 mm", marca: "", decor: "Blanco", espesor: 18000, veta: false, formato: null }];
    const r = azar(20261116);
    const columnas = { numero: [], placa: [], largo: [], ancho: [], veta: [], fecha: [] };
    const desde = Math.floor(Date.UTC(2026, 0, 5) / DIA_MS);
    for (let i = 0; i < cantidad; i++) {
      const p = Math.floor(r() * placas.length);
      const formato = placas[p].formato || [2750000, 1830000];
      const largo = Math.round((150 + r() * (formato[0] / UM_POR_MM - 150)) * 10) / 10;
      const tope = Math.min(largo, formato[1] / UM_POR_MM);
      const ancho = Math.round((60 + Math.pow(r(), 1.6) * Math.max(0, tope - 60)) * 10) / 10;
      columnas.numero.push(i + 1);
      columnas.placa.push(p);
      columnas.largo.push(Math.round(Math.max(largo, ancho) * UM_POR_MM));
      columnas.ancho.push(Math.round(Math.min(largo, ancho) * UM_POR_MM));
      // en el ejemplo, una placa sin el dato de la veta la lleva a veces, para que se vea cómo se muestra
      const conVeta = placas[p].veta === true || (placas[p].veta == null && r() < 0.3);
      columnas.veta.push(conVeta ? 1 + Math.floor(r() * 2) : 0);
      columnas.fecha.push(desde + Math.floor(r() * 300));
    }
    return { ...datos, placas, sobrantes: columnas, formas: [] };
  }

  function preparar(datos, ejemplo, reales) {
    const s = datos.sobrantes;
    const n = s.numero.length;
    D.n = n;
    D.ejemplo = ejemplo;
    D.numero = Int32Array.from(s.numero);
    D.placa = Uint16Array.from(s.placa);
    D.largo = Float64Array.from(s.largo, (v) => v / UM_POR_MM);
    D.ancho = Float64Array.from(s.ancho, (v) => v / UM_POR_MM);
    D.veta = Uint8Array.from(s.veta);
    D.fecha = Int32Array.from(s.fecha);
    // Los retazos con forma (en L, en U): sus esquinas y los rectángulos más grandes que entran, en mm.
    D.forma = new Array(n).fill(null);
    for (const f of datos.formas || []) {
      const puntos = [];
      for (let k = 0; k + 1 < f.puntos.length; k += 2) puntos.push([f.puntos[k] / UM_POR_MM, f.puntos[k + 1] / UM_POR_MM]);
      const rects = [];
      for (let k = 0; k + 3 < f.rectangulos.length; k += 4) rects.push(f.rectangulos.slice(k, k + 4).map((v) => v / UM_POR_MM));
      D.forma[f.fila] = { puntos, rects };
    }
    D.area = new Float64Array(n);
    let maxLargo = 0;
    let maxAncho = 0;
    for (let i = 0; i < n; i++) {
      D.area[i] = D.forma[i] ? superficieDe(D.forma[i].puntos) : D.largo[i] * D.ancho[i];
      if (D.largo[i] > maxLargo) maxLargo = D.largo[i];
      if (D.ancho[i] > maxAncho) maxAncho = D.ancho[i];
    }
    D.maxLargo = maxLargo;
    D.maxAncho = maxAncho;
    D.placas = datos.placas.map((p) => ({
      ...p,
      corto: p.corto || p.nombre,
      espesorMm: p.espesor == null ? null : p.espesor / UM_POR_MM,
    }));
    D.textoDePlaca = D.placas.map((p) =>
      normalizar(
        [p.corto, p.nombre, p.marca, p.decor, p.id, p.espesorMm == null ? "" : `${mm(p.espesorMm)} mm ${mm(p.espesorMm)}mm`].join(" "),
      ),
    );
    D.espesores = [...new Set(D.placas.map((p) => p.espesorMm))].sort((a, b) => (a ?? -1) - (b ?? -1));
    D.espesorDePlaca = Uint16Array.from(D.placas, (p) => D.espesores.indexOf(p.espesorMm));
    D.porPlaca = new Uint32Array(D.placas.length);
    for (let i = 0; i < n; i++) D.porPlaca[D.placa[i]]++;
    const porNombre = D.placas.map((_, i) => i).sort((a, b) => D.placas[a].corto.localeCompare(D.placas[b].corto, "es"));
    D.rangoDePlaca = new Uint16Array(D.placas.length);
    porNombre.forEach((p, rango) => (D.rangoDePlaca[p] = rango));
    D.placasPorNombre = porNombre;
    D.permutaciones = new Map();
    D.resultado = new Uint32Array(n);
    D.entran = new Uint32Array(n); // cuántas piezas entran en cada recorte del resultado (mismo orden)
    D.facetaPlaca = new Uint32Array(D.placas.length);
    D.facetaEspesor = new Uint32Array(D.espesores.length);

    $("estado").textContent = ejemplo
      ? `Ejemplo: ${nF.format(n)} recortes inventados`
      : `${nF.format(n)} recorte${n === 1 ? "" : "s"} guardado${n === 1 ? "" : "s"}`;
    if (ejemplo) {
      $("aviso").hidden = false;
      if (reales) {
        $("aviso-titulo").textContent = `Ejemplo con ${nF.format(n)} recortes inventados`;
        $("aviso-texto").textContent = `No son tus recortes. Para ver los ${nF.format(reales)} que tenés guardados, sacá «?ejemplo» de la dirección.`;
      } else {
        $("aviso-titulo").textContent = "Todavía no hay recortes guardados";
        $("aviso-texto").textContent =
          "Lo que ves son recortes inventados, para mostrar cómo funciona la página: no son tuyos. Cuando guardes el primero al final de un pedido, acá aparecen los tuyos.";
      }
      document.title = "Sobrantes del taller (ejemplo)";
    }
    armarFiltros();
    conectar();
    $("cargando").hidden = true;
    $("app").hidden = false;
    if (window.matchMedia("(max-width: 1056px)").matches) $("plegable").open = false;
    medirFila();
    prepararGrafico();
    actualizar();
  }

  // ----------------------------------------------------------------------------------------------- ordenar y filtrar

  /* La permutación de los recortes para una clave, de menor a mayor (se arma una vez y se guarda). */
  function permutacion(clave) {
    const guardada = D.permutaciones.get(clave);
    if (guardada) return guardada;
    const n = D.n;
    const indices = new Uint32Array(n);
    for (let i = 0; i < n; i++) indices[i] = i;
    const N = D.numero;
    let comparar;
    if (clave === "numero") comparar = (a, b) => N[a] - N[b];
    else if (clave === "largo") comparar = (a, b) => D.largo[a] - D.largo[b] || D.ancho[a] - D.ancho[b] || N[a] - N[b];
    else if (clave === "fecha") comparar = (a, b) => D.fecha[a] - D.fecha[b] || N[a] - N[b];
    else if (clave === "placa") comparar = (a, b) => D.rangoDePlaca[D.placa[a]] - D.rangoDePlaca[D.placa[b]] || N[a] - N[b];
    else comparar = (a, b) => D.area[a] - D.area[b] || N[a] - N[b];
    indices.sort(comparar);
    D.permutaciones.set(clave, indices);
    return indices;
  }

  function leerFiltros() {
    const texto = normalizar($("buscar").value).trim();
    F.tokens = [];
    F.numero = -1;
    for (const t of texto.split(/\s+/).filter(Boolean)) {
      const conS = /^s(\d+)$/.exec(t);
      if (conS) F.numero = parseInt(conS[1], 10);
      else F.tokens.push(t);
    }
    F.largo = numeroDe($("pieza-largo"));
    F.ancho = numeroDe($("pieza-ancho"));
    F.margen = numeroDe($("margen"));
    F.separacion = numeroDe($("separacion"));
    F.respetarVeta = $("respetar-veta").checked;
    F.veta = document.querySelector('input[name="veta"]:checked').value;
  }

  /* Cuántas piezas entran en el recorte i, en filas y columnas, con el margen del borde y la separación entre piezas;
     0 si no entra ninguna. Con la veta respetada, el largo de la pieza va para el lado de la veta. */
  /* n piezas de lado p entran en un largo d si n·p + (n − 1)·separación ≤ d − 2·margen. */
  function enUnLado(d, p) {
    return Math.max(0, Math.floor((d - 2 * F.margen + F.separacion) / (p + F.separacion)));
  }

  function cuantasEntran(i) {
    if (D.forma[i]) return llenarForma(i).cuantas;
    const derecha = enUnLado(D.largo[i], F.largo) * enUnLado(D.ancho[i], F.ancho); // el largo de la pieza a lo largo
    const girada = enUnLado(D.largo[i], F.ancho) * enUnLado(D.ancho[i], F.largo);
    const v = D.veta[i];
    if (F.respetarVeta && v === 1) return derecha;
    if (F.respetarVeta && v === 2) return girada;
    return Math.max(derecha, girada);
  }

  /* La superficie de un polígono (sus esquinas en orden), en mm². */
  function superficieDe(puntos) {
    let doble = 0;
    for (let k = 0; k < puntos.length; k++) {
      const [x0, y0] = puntos[k];
      const [x1, y1] = puntos[(k + 1) % puntos.length];
      doble += x0 * y1 - x1 * y0;
    }
    return Math.abs(doble) / 2;
  }

  function textoDeForma(i) {
    const f = D.forma[i];
    if (!f) return "";
    return f.puntos.length === 6 ? "en L" : `con forma de ${f.puntos.length} esquinas`;
  }

  /* Cuántas piezas entran en filas y columnas en un rectángulo de w × h al que ya se le sacó el margen del borde, y si
     van giradas (con la veta respetada, el largo de la pieza va para el lado de la veta). */
  function enRectangulo(w, h, v) {
    const lado = (d, p) => Math.max(0, Math.floor((d + F.separacion) / (p + F.separacion)));
    const derecha = lado(w, F.largo) * lado(h, F.ancho);
    const girada = lado(w, F.ancho) * lado(h, F.largo);
    if (F.respetarVeta && v === 1) return { n: derecha, girada: false };
    if (F.respetarVeta && v === 2) return { n: girada, girada: true };
    return derecha >= girada ? { n: derecha, girada: false } : { n: girada, girada: true };
  }

  /* Los rectángulos de un retazo con forma, cortados en franjas por todas sus esquinas (paradas o acostadas): cada
     franja se llena aparte. Dos tramos seguidos de la misma altura son una sola franja. */
  function franjas(rects, paradas) {
    const a = paradas ? 0 : 1;
    const b = 1 - a;
    const cortes = [...new Set(rects.flatMap((r) => [r[a], r[a + 2]]))].sort((p, q) => p - q);
    const tramos = [];
    for (let k = 0; k + 1 < cortes.length; k++) {
      const desde = cortes[k];
      const hasta = cortes[k + 1];
      const cubren = rects
        .filter((r) => r[a] <= desde && r[a + 2] >= hasta)
        .map((r) => [r[b], r[b + 2]])
        .sort((p, q) => p[0] - q[0]);
      const unidos = [];
      for (const c of cubren) {
        const u = unidos[unidos.length - 1];
        if (u && c[0] <= u[1]) u[1] = Math.max(u[1], c[1]);
        else unidos.push([c[0], c[1]]);
      }
      for (const u of unidos) tramos.push([desde, hasta, u[0], u[1]]);
    }
    tramos.sort((p, q) => p[2] - q[2] || p[3] - q[3] || p[0] - q[0]);
    const juntos = [];
    for (const t of tramos) {
      const u = juntos[juntos.length - 1];
      if (u && u[2] === t[2] && u[3] === t[3] && u[1] === t[0]) u[1] = t[1];
      else juntos.push([...t]);
    }
    return juntos.map((t) => (paradas ? [t[0], t[2], t[1], t[3]] : [t[2], t[0], t[3], t[1]]));
  }

  /* Cuántas piezas entran en un retazo con forma: sus rectángulos más grandes, achicados por el margen del borde
     (cualquier pieza con su margen que entra en la forma entra en uno de ellos); la mejor de tres maneras: el mejor
     rectángulo solo, franjas paradas o franjas acostadas. Es una cuenta para buscar, no el acomodo del motor. */
  function llenarForma(i) {
    const m = F.margen;
    const rects = D.forma[i].rects
      .map((r) => [r[0] + m, r[1] + m, r[2] - m, r[3] - m])
      .filter((r) => r[2] > r[0] && r[3] > r[1]);
    const v = D.veta[i];
    let mejor = { cuantas: 0, partes: [] };
    const probar = (partes) => {
      let total = 0;
      const llenas = partes.map((r) => {
        const e = enRectangulo(r[2] - r[0], r[3] - r[1], v);
        total += e.n;
        return { r, girada: e.girada };
      });
      if (total > mejor.cuantas) mejor = { cuantas: total, partes: llenas };
    };
    for (const r of rects) probar([r]);
    probar(franjas(rects, true));
    probar(franjas(rects, false));
    return mejor;
  }

  function filtrar() {
    const n = D.n;
    const placas = D.placas.length;
    const textoOk = new Uint8Array(placas);
    const espesorOk = new Uint8Array(placas);
    const placaOk = new Uint8Array(placas);
    for (let p = 0; p < placas; p++) {
      const texto = D.textoDePlaca[p];
      textoOk[p] = F.tokens.every((t) => texto.includes(t)) ? 1 : 0;
      espesorOk[p] = F.espesores.size === 0 || F.espesores.has(D.espesorDePlaca[p]) ? 1 : 0;
      placaOk[p] = F.placas.size === 0 || F.placas.has(p) ? 1 : 0;
    }
    const pieza = F.largo > 0 && F.ancho > 0;
    const veta = F.veta === "con" ? 1 : F.veta === "sin" ? 0 : -1;
    const P = D.placa;
    const N = D.numero;
    const VE = D.veta;
    const porEspesor = D.espesorDePlaca;
    const resultado = D.resultado;
    const entran = D.entran;
    const facetaPlaca = D.facetaPlaca.fill(0);
    const facetaEspesor = D.facetaEspesor.fill(0);
    const orden = permutacion(V.clave === "entran" ? "area" : V.clave);
    const desc = V.clave === "entran" ? true : V.desc;
    let k = 0;
    for (let j = 0; j < n; j++) {
      const i = orden[desc ? n - 1 - j : j];
      const p = P[i];
      if (!textoOk[p]) continue;
      if (F.numero >= 0 && N[i] !== F.numero) continue;
      if (veta === 1 ? VE[i] === 0 : veta === 0 ? VE[i] !== 0 : false) continue;
      let cuantas = 0;
      if (pieza) {
        cuantas = cuantasEntran(i);
        if (cuantas === 0) continue;
      }
      const okEspesor = espesorOk[p];
      const okPlaca = placaOk[p];
      if (okEspesor) facetaPlaca[p]++;
      if (okPlaca) facetaEspesor[porEspesor[p]]++;
      if (okEspesor && okPlaca) {
        resultado[k] = i;
        entran[k] = cuantas;
        k++;
      }
    }
    if (V.clave === "entran" && pieza && k > 1) {
      const pares = Array.from({ length: k }, (_, x) => [entran[x], resultado[x]]);
      pares.sort((a, b) => (V.desc ? b[0] - a[0] : a[0] - b[0]) || D.area[b[1]] - D.area[a[1]]);
      pares.forEach(([e, i], x) => {
        entran[x] = e;
        resultado[x] = i;
      });
    }
    V.cuantos = k;
    V.pieza = pieza;
  }

  // ----------------------------------------------------------------------------------------------- los filtros

  function armarFiltros() {
    const espesores = $("espesores");
    espesores.textContent = "";
    if (D.espesores.length < 2) $("grupo-espesor").hidden = true;
    D.espesores.forEach((e, x) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "etiqueta-filtro";
      b.dataset.espesor = String(x);
      b.setAttribute("aria-pressed", "false");
      b.innerHTML = `<span>${e == null ? "Sin dato" : `${escapar(mm(e))} mm`}</span><span class="cuantos"></span>`;
      espesores.append(b);
    });
    const lista = $("placas");
    lista.textContent = "";
    for (const p of D.placasPorNombre) {
      const placa = D.placas[p];
      const fila = document.createElement("label");
      fila.dataset.placa = String(p);
      fila.dataset.texto = D.textoDePlaca[p];
      fila.title = placa.nombre;
      fila.innerHTML = `<input type="checkbox" value="${p}"><span class="nombre">${escapar(placa.corto)}</span><span class="cuantos"></span>`;
      lista.append(fila);
    }
  }

  function pintarFacetas() {
    for (const b of $("espesores").children) {
      const x = Number(b.dataset.espesor);
      b.querySelector(".cuantos").textContent = nF.format(D.facetaEspesor[x]);
      b.setAttribute("aria-pressed", F.espesores.has(x) ? "true" : "false");
    }
    for (const fila of $("placas").children) {
      const p = Number(fila.dataset.placa);
      const cuantos = fila.querySelector(".cuantos");
      cuantos.textContent = nF.format(D.facetaPlaca[p]);
      cuantos.classList.toggle("sin", D.facetaPlaca[p] === 0);
      fila.querySelector("input").checked = F.placas.has(p);
    }
    const activos =
      (F.tokens.length || F.numero >= 0 ? 1 : 0) +
      (F.largo > 0 && F.ancho > 0 ? 1 : 0) +
      (F.veta !== "todas" ? 1 : 0) +
      (F.espesores.size ? 1 : 0) +
      (F.placas.size ? 1 : 0);
    $("filtros-activos").textContent = activos ? `${activos} filtro${activos === 1 ? "" : "s"}` : "";
  }

  function limpiar() {
    $("buscar").value = "";
    $("pieza-largo").value = "";
    $("pieza-ancho").value = "";
    $("margen").value = "0";
    $("separacion").value = "0";
    $("respetar-veta").checked = true;
    document.querySelector('input[name="veta"][value="todas"]').checked = true;
    $("buscar-placa").value = "";
    for (const fila of $("placas").children) fila.hidden = false;
    F.espesores.clear();
    F.placas.clear();
    actualizar();
  }

  function conectar() {
    let espera = 0;
    const pronto = () => {
      clearTimeout(espera);
      espera = setTimeout(actualizar, 90);
    };
    for (const id of ["buscar", "pieza-largo", "pieza-ancho", "margen", "separacion"]) $(id).addEventListener("input", pronto);
    $("respetar-veta").addEventListener("change", actualizar);
    for (const r of document.querySelectorAll('input[name="veta"]')) r.addEventListener("change", actualizar);
    $("espesores").addEventListener("click", (e) => {
      const b = e.target.closest("button");
      if (!b) return;
      const x = Number(b.dataset.espesor);
      if (F.espesores.has(x)) F.espesores.delete(x);
      else F.espesores.add(x);
      actualizar();
    });
    $("placas").addEventListener("change", (e) => {
      const p = Number(e.target.value);
      if (e.target.checked) F.placas.add(p);
      else F.placas.delete(p);
      actualizar();
    });
    $("buscar-placa").addEventListener("input", () => {
      const t = normalizar($("buscar-placa").value).trim();
      for (const fila of $("placas").children) fila.hidden = Boolean(t) && !fila.dataset.texto.includes(t);
    });
    $("limpiar").addEventListener("click", limpiar);
    $("limpiar-2").addEventListener("click", limpiar);
    $("barras").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-placa]");
      if (!b) return;
      const p = Number(b.dataset.placa);
      if (F.placas.has(p)) F.placas.delete(p);
      else F.placas.add(p);
      actualizar();
    });
    for (const c of document.querySelectorAll(".tabla__cabecera [data-orden]")) {
      c.querySelector("button").addEventListener("click", () => {
        const clave = c.dataset.orden;
        if (V.clave === clave) V.desc = !V.desc;
        else {
          V.clave = clave;
          V.desc = clave === "area" || clave === "fecha" || clave === "largo" || clave === "entran";
        }
        actualizar();
      });
    }
    const cuerpo = $("cuerpo");
    let cuadro = 0;
    cuerpo.addEventListener("scroll", () => {
      if (!cuadro) cuadro = requestAnimationFrame(() => ((cuadro = 0), pintarTabla()));
    });
    cuerpo.addEventListener("click", (e) => {
      const fila = e.target.closest(".tabla__fila");
      if (fila && fila.dataset.indice) elegir(Number(fila.dataset.indice));
    });
    cuerpo.addEventListener("keydown", moverConTeclas);
    $("copiar").addEventListener("click", copiarNumero);
    let medidas = 0;
    window.addEventListener("resize", () => {
      cancelAnimationFrame(medidas);
      medidas = requestAnimationFrame(() => {
        medirFila();
        prepararGrafico();
        pintarGrafico();
        pintarTabla();
      });
    });
  }

  function actualizar() {
    const desde = performance.now();
    leerFiltros();
    filtrar();
    if (V.cuantos && (V.elegido < 0 || posicionEnResultado(V.elegido) < 0)) V.elegido = D.resultado[0];
    pintarFacetas();
    pintarDatos();
    pintarBarras();
    pintarGrafico();
    pintarCabecera();
    pintarTabla(true);
    pintarDetalle();
    document.body.dataset.ms = (performance.now() - desde).toFixed(1); // para medir: cuánto tardó la última búsqueda
  }

  // ----------------------------------------------------------------------------------------------- los datos grandes y las barras

  function pintarDatos() {
    const k = V.cuantos;
    const R = D.resultado;
    let area = 0;
    let mayor = -1;
    const usadas = new Uint8Array(D.placas.length);
    let distintas = 0;
    for (let x = 0; x < k; x++) {
      const i = R[x];
      area += D.area[i];
      if (mayor < 0 || D.area[i] > D.area[mayor]) mayor = i;
      if (!usadas[D.placa[i]]) {
        usadas[D.placa[i]] = 1;
        distintas++;
      }
    }
    const filtrado = k !== D.n;
    $("d-cantidad").textContent = nF.format(k);
    $("d-cantidad-nota").textContent = D.ejemplo
      ? filtrado
        ? `de ${nF.format(D.n)} de ejemplo`
        : "de ejemplo"
      : filtrado
        ? `de ${nF.format(D.n)} guardados`
        : "guardados";
    $("d-superficie").textContent = metros2(area);
    $("d-superficie-nota").textContent = k ? `${metros2(k ? area / k : 0)} por recorte` : "";
    $("d-placas").textContent = nF.format(distintas);
    $("d-placas-nota").textContent = filtrado ? `de ${nF.format(D.placas.length)}` : "";
    if (mayor >= 0) {
      $("d-mayor").textContent = medida(D.largo[mayor], D.ancho[mayor]);
      $("d-mayor-nota").textContent = `S${D.numero[mayor]} · ${D.placas[D.placa[mayor]].corto}`;
    } else {
      $("d-mayor").textContent = "—";
      $("d-mayor-nota").textContent = "";
    }
    $("cuenta").textContent = filtrado
      ? `${nF.format(k)} de ${nF.format(D.n)}${V.pieza ? " · donde entra la pieza" : ""}`
      : `${nF.format(k)} en total`;
  }

  function pintarBarras() {
    const k = V.cuantos;
    const R = D.resultado;
    const area = new Float64Array(D.placas.length);
    const cuantos = new Uint32Array(D.placas.length);
    for (let x = 0; x < k; x++) {
      const p = D.placa[R[x]];
      area[p] += D.area[R[x]];
      cuantos[p]++;
    }
    const con = [];
    for (let p = 0; p < D.placas.length; p++) if (cuantos[p]) con.push(p);
    con.sort((a, b) => area[b] - area[a] || D.rangoDePlaca[a] - D.rangoDePlaca[b]);
    const filas = con.slice(0, BARRAS).map((p) => ({ p, nombre: D.placas[p].corto, area: area[p], cuantos: cuantos[p] }));
    const resto = con.slice(BARRAS);
    if (resto.length) {
      filas.push({
        p: -1,
        nombre: `Otras ${resto.length} placas`,
        area: resto.reduce((s, p) => s + area[p], 0),
        cuantos: resto.reduce((s, p) => s + cuantos[p], 0),
      });
    }
    const tope = filas.reduce((m, f) => Math.max(m, f.area), 0) || 1;
    const lista = $("barras");
    if (!filas.length) {
      lista.innerHTML = '<li class="barras__vacio">Nada para mostrar con estos filtros.</li>';
      return;
    }
    lista.innerHTML = filas
      .map((f) => {
        const ancho = Math.max(0.5, (100 * f.area) / tope).toFixed(2);
        const valor = `${metros2(f.area)} · ${nF.format(f.cuantos)}`;
        const titulo = `${f.nombre}: ${metros2(f.area)} en ${nF.format(f.cuantos)} recorte${f.cuantos === 1 ? "" : "s"}`;
        if (f.p < 0) {
          return `<li><div class="barra barra--otras" title="${escapar(titulo)}"><span class="barra__nombre">${escapar(f.nombre)}</span><span class="barra__valor">${valor}</span><span class="barra__pista"><span class="barra__lleno" style="display:block;width:${ancho}%"></span></span></div></li>`;
        }
        return `<li><button type="button" class="barra" data-placa="${f.p}" aria-pressed="${F.placas.has(f.p)}" title="${escapar(titulo)}"><span class="barra__nombre">${escapar(f.nombre)}</span><span class="barra__valor">${valor}</span><span class="barra__pista"><span class="barra__lleno" style="display:block;width:${ancho}%"></span></span></button></li>`;
      })
      .join("");
  }

  // ----------------------------------------------------------------------------------------------- el gráfico

  const G = { lienzo: null, ctx: null, fondo: null, ancho: 0, alto: 0, ppp: 1, m: { izq: 52, der: 14, arr: 28, aba: 34 } };

  function color(nombre) {
    return getComputedStyle(document.documentElement).getPropertyValue(nombre).trim();
  }

  function redondoArriba(v) {
    if (v <= 0) return 1000;
    const potencia = Math.pow(10, Math.floor(Math.log10(v)));
    for (const f of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (f * potencia >= v) return f * potencia;
    return 10 * potencia;
  }

  function paso(rango, marcas) {
    const crudo = rango / marcas;
    const potencia = Math.pow(10, Math.floor(Math.log10(crudo)));
    for (const f of [1, 2, 2.5, 5, 10]) if (f * potencia >= crudo) return f * potencia;
    return 10 * potencia;
  }

  function prepararGrafico() {
    const lienzo = $("dispersion");
    const caja = $("lienzo").getBoundingClientRect();
    G.lienzo = lienzo;
    G.ancho = Math.max(200, caja.width);
    G.alto = Math.max(160, caja.height);
    G.ppp = Math.min(window.devicePixelRatio || 1, 2);
    lienzo.width = Math.round(G.ancho * G.ppp);
    lienzo.height = Math.round(G.alto * G.ppp);
    G.ctx = lienzo.getContext("2d");
    G.xMax = redondoArriba(Math.max(D.maxLargo, 1));
    G.yMax = redondoArriba(Math.max(D.maxAncho, 1));
    G.x = (v) => G.m.izq + (v / G.xMax) * (G.ancho - G.m.izq - G.m.der);
    G.y = (v) => G.alto - G.m.aba - (v / G.yMax) * (G.alto - G.m.arr - G.m.aba);
    pintarFondoDelGrafico();
  }

  function radioDePunto(n) {
    return n > MUCHOS_PUNTOS ? 0 : n > 400 ? 2.5 : 4;
  }

  /* La grilla, los ejes y todos los recortes en gris: no cambia con los filtros, se dibuja una vez por tamaño. */
  function pintarFondoDelGrafico() {
    const fondo = document.createElement("canvas");
    fondo.width = G.lienzo.width;
    fondo.height = G.lienzo.height;
    const c = fondo.getContext("2d");
    c.scale(G.ppp, G.ppp);
    const linea = color("--borde");
    const texto = color("--texto-2");
    c.font = '11px "IBM Plex Sans", "Helvetica Neue", Arial, sans-serif';
    c.fillStyle = texto;
    c.strokeStyle = linea;
    c.lineWidth = 1;
    const pasoX = paso(G.xMax, Math.max(2, Math.floor((G.ancho - 80) / 90)));
    const pasoY = paso(G.yMax, Math.max(2, Math.floor((G.alto - 60) / 50)));
    c.textAlign = "center";
    c.textBaseline = "top";
    for (let v = 0; v <= G.xMax + 1e-6; v += pasoX) {
      const x = Math.round(G.x(v)) + 0.5;
      c.beginPath();
      c.moveTo(x, G.m.arr);
      c.lineTo(x, G.alto - G.m.aba);
      c.stroke();
      c.fillText(mm(v), x, G.alto - G.m.aba + 6);
    }
    c.textAlign = "right";
    c.textBaseline = "middle";
    for (let v = 0; v <= G.yMax + 1e-6; v += pasoY) {
      const y = Math.round(G.y(v)) + 0.5;
      c.beginPath();
      c.moveTo(G.m.izq, y);
      c.lineTo(G.ancho - G.m.der, y);
      c.stroke();
      c.fillText(mm(v), G.m.izq - 8, y);
    }
    // largo = ancho: los recortes cuadrados quedan sobre esta línea (ninguno queda arriba: el largo es el lado mayor)
    const hasta = Math.min(G.xMax, G.yMax);
    c.setLineDash([4, 4]);
    c.strokeStyle = color("--borde-fuerte");
    c.beginPath();
    c.moveTo(G.x(0), G.y(0));
    c.lineTo(G.x(hasta), G.y(hasta));
    c.stroke();
    c.setLineDash([]);
    c.textAlign = "right";
    c.textBaseline = "alphabetic";
    c.fillText("Largo (mm)", G.ancho - G.m.der, G.alto - 4);
    c.textAlign = "left";
    c.textBaseline = "top";
    c.fillText("Ancho (mm)", 4, 2);
    // todos los recortes, en gris: los que no cumplen con la búsqueda quedan así
    c.fillStyle = color("--serie-tenue");
    pintarPuntos(c, null, D.n);
    G.fondo = fondo;
  }

  function pintarPuntos(c, indices, cuantos) {
    const r = radioDePunto(D.n);
    const L = D.largo;
    const A = D.ancho;
    if (r === 0) {
      const lado = 2;
      for (let x = 0; x < cuantos; x++) {
        const i = indices ? indices[x] : x;
        c.fillRect(G.x(L[i]) - 1, G.y(A[i]) - 1, lado, lado);
      }
      return;
    }
    c.beginPath();
    for (let x = 0; x < cuantos; x++) {
      const i = indices ? indices[x] : x;
      const px = G.x(L[i]);
      const py = G.y(A[i]);
      c.moveTo(px + r, py);
      c.arc(px, py, r, 0, Math.PI * 2);
    }
    c.fill();
  }

  function pintarGrafico() {
    if (!G.ctx) return;
    const c = G.ctx;
    c.setTransform(1, 0, 0, 1, 0, 0);
    c.clearRect(0, 0, G.lienzo.width, G.lienzo.height);
    c.drawImage(G.fondo, 0, 0);
    c.scale(G.ppp, G.ppp);
    if (V.pieza) {
      // donde entra la pieza girándola (sin contar la veta): de su medida, con el margen, para arriba y a la derecha
      const l = Math.max(F.largo, F.ancho) + 2 * F.margen;
      const a = Math.min(F.largo, F.ancho) + 2 * F.margen;
      const x0 = Math.min(G.x(l), G.ancho - G.m.der);
      const y0 = Math.max(G.y(a), G.m.arr);
      c.fillStyle = color("--zona");
      c.fillRect(x0, G.m.arr, G.ancho - G.m.der - x0, y0 - G.m.arr);
      c.setLineDash([4, 3]);
      c.strokeStyle = color("--zona-borde");
      c.strokeRect(x0 + 0.5, G.m.arr + 0.5, G.ancho - G.m.der - x0 - 1, y0 - G.m.arr - 1);
      c.setLineDash([]);
    }
    c.fillStyle = color("--serie");
    pintarPuntos(c, D.resultado, V.cuantos);
    if (V.elegido >= 0) {
      const px = G.x(D.largo[V.elegido]);
      const py = G.y(D.ancho[V.elegido]);
      c.lineWidth = 2;
      c.strokeStyle = color("--fondo");
      c.beginPath();
      c.arc(px, py, 8, 0, Math.PI * 2);
      c.stroke();
      c.strokeStyle = color("--texto");
      c.beginPath();
      c.arc(px, py, 6, 0, Math.PI * 2);
      c.stroke();
    }
    const leyenda = [];
    const filtrado = V.cuantos !== D.n;
    leyenda.push(`<span><i style="background:var(--serie)"></i>${filtrado ? "Cumple con lo que buscás" : "Recorte"}</span>`);
    if (filtrado) leyenda.push('<span><i style="background:var(--serie-tenue)"></i>No cumple</span>');
    if (V.pieza) leyenda.push('<span><i class="zona"></i>Entra la pieza girándola</span>');
    $("leyenda").innerHTML = leyenda.join("");
  }

  function masCercano(px, py, radio) {
    let mejor = -1;
    let distancia = radio * radio;
    const R = D.resultado;
    for (let x = 0; x < V.cuantos; x++) {
      const i = R[x];
      const dx = G.x(D.largo[i]) - px;
      const dy = G.y(D.ancho[i]) - py;
      const d = dx * dx + dy * dy;
      if (d <= distancia) {
        distancia = d;
        mejor = i;
      }
    }
    return mejor;
  }

  function conectarGrafico() {
    const lienzo = $("dispersion");
    const globo = $("globo");
    let cuadro = 0;
    let ultimo = null;
    const mirar = () => {
      cuadro = 0;
      if (!ultimo) return;
      const i = masCercano(ultimo.x, ultimo.y, CERCA_PX);
      if (i < 0) {
        globo.hidden = true;
        return;
      }
      const placa = D.placas[D.placa[i]];
      globo.innerHTML = `<strong>S${D.numero[i]}</strong> · ${escapar(medida(D.largo[i], D.ancho[i]))} mm<br>${escapar(placa.corto)}<br>${CORTO_VETA[D.veta[i]]} · ${fechaTexto(D.fecha[i])}`;
      globo.hidden = false;
      const x = G.x(D.largo[i]);
      const y = G.y(D.ancho[i]);
      const derecha = x + 16 + globo.offsetWidth > G.ancho;
      globo.style.left = `${derecha ? x - 16 - globo.offsetWidth : x + 16}px`;
      globo.style.top = `${Math.max(4, Math.min(G.alto - globo.offsetHeight - 4, y - globo.offsetHeight / 2))}px`;
    };
    lienzo.addEventListener("pointermove", (e) => {
      const r = lienzo.getBoundingClientRect();
      ultimo = { x: e.clientX - r.left, y: e.clientY - r.top };
      if (!cuadro) cuadro = requestAnimationFrame(mirar);
    });
    lienzo.addEventListener("pointerleave", () => {
      ultimo = null;
      globo.hidden = true;
    });
    lienzo.addEventListener("click", (e) => {
      const r = lienzo.getBoundingClientRect();
      const i = masCercano(e.clientX - r.left, e.clientY - r.top, e.pointerType === "touch" ? CERCA_PX * 2 : CERCA_PX);
      if (i >= 0) elegir(i, true);
    });
  }

  // ----------------------------------------------------------------------------------------------- la tabla

  function medirFila() {
    V.fila = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--fila")) || 48;
  }

  function pintarCabecera() {
    const tabla = $("tabla");
    tabla.classList.toggle("tabla--pieza", V.pieza);
    for (const c of document.querySelectorAll(".tabla__cabecera [data-orden]")) {
      if (c.dataset.orden === "entran") c.hidden = !V.pieza;
      if (c.dataset.orden === V.clave) c.setAttribute("aria-sort", V.desc ? "descending" : "ascending");
      else c.removeAttribute("aria-sort");
    }
    if (V.clave === "entran" && !V.pieza) {
      V.clave = "area";
      V.desc = true;
    }
    tabla.setAttribute("aria-rowcount", String(V.cuantos + 1));
    $("vacio").hidden = V.cuantos > 0;
    tabla.hidden = V.cuantos === 0;
  }

  const filas = [];

  function filaNueva() {
    const fila = document.createElement("div");
    fila.className = "tabla__fila";
    fila.setAttribute("role", "row");
    fila.innerHTML =
      '<div class="celda c-dibujo" role="cell"><span class="miniatura"><i></i></span></div>' +
      '<div class="celda c-numero numero" role="cell"></div>' +
      '<div class="celda c-placa celda--dos" role="cell"><span class="arriba"></span><span class="marca"></span><span class="resumen"></span></div>' +
      '<div class="celda c-medida numero" role="cell"></div>' +
      '<div class="celda c-area numero" role="cell"></div>' +
      '<div class="celda c-fecha numero" role="cell"></div>' +
      '<div class="celda c-entran numero" role="cell"></div>';
    fila.partes = {
      mini: fila.querySelector(".miniatura i"),
      numero: fila.children[1],
      placa: fila.querySelector(".arriba"),
      marca: fila.querySelector(".marca"),
      resumen: fila.querySelector(".resumen"),
      medida: fila.children[3],
      area: fila.children[4],
      fecha: fila.children[5],
      entran: fila.children[6],
    };
    return fila;
  }

  function pintarTabla(volverArriba) {
    const cuerpo = $("cuerpo");
    if (volverArriba) cuerpo.scrollTop = 0;
    const alto = V.fila;
    $("alto").style.height = `${V.cuantos * alto}px`;
    const arriba = cuerpo.scrollTop;
    const desde = Math.max(0, Math.floor(arriba / alto) - 6);
    const hasta = Math.min(V.cuantos, Math.ceil((arriba + cuerpo.clientHeight) / alto) + 6);
    const hacen = hasta - desde;
    while (filas.length < hacen) {
      const f = filaNueva();
      filas.push(f);
      cuerpo.append(f);
    }
    const escalaMini = Math.min(40 / Math.max(D.maxLargo, 1), 28 / Math.max(D.maxAncho, 1));
    for (let x = 0; x < filas.length; x++) {
      const f = filas[x];
      const posicion = desde + x;
      if (posicion >= hasta) {
        f.hidden = true;
        continue;
      }
      const i = D.resultado[posicion];
      const p = f.partes;
      f.hidden = false;
      f.style.transform = `translateY(${posicion * alto}px)`;
      f.dataset.indice = String(i);
      f.setAttribute("aria-rowindex", String(posicion + 2));
      f.setAttribute("aria-selected", i === V.elegido ? "true" : "false");
      const placa = D.placas[D.placa[i]];
      p.mini.style.width = `${Math.max(3, D.largo[i] * escalaMini)}px`;
      p.mini.style.height = `${Math.max(3, D.ancho[i] * escalaMini)}px`;
      p.mini.className = D.veta[i] === 1 ? "con-veta-largo" : D.veta[i] === 2 ? "con-veta-ancho" : "";
      p.mini.style.clipPath = D.forma[i]
        ? `polygon(${D.forma[i].puntos
            .map(([x, y]) => `${((x / D.largo[i]) * 100).toFixed(1)}% ${((1 - y / D.ancho[i]) * 100).toFixed(1)}%`)
            .join(", ")})`
        : "";
      const forma = textoDeForma(i);
      p.numero.textContent = `S${D.numero[i]}`;
      p.placa.textContent = placa.corto;
      p.placa.title = placa.nombre;
      const veta = forma ? `${NOMBRE_VETA[D.veta[i]]} · ${forma}` : NOMBRE_VETA[D.veta[i]];
      p.marca.textContent = placa.marca ? `${placa.marca} · ${veta}` : veta;
      p.resumen.textContent = `${medida(D.largo[i], D.ancho[i])} mm${forma ? `, ${forma}` : ""} · ${CORTO_VETA[D.veta[i]]}${
        V.pieza ? ` · entran ${nF.format(D.entran[posicion])}` : ""
      }`;
      p.medida.textContent = medida(D.largo[i], D.ancho[i]);
      p.area.textContent = m2F.format(D.area[i] / MM2_POR_M2);
      p.fecha.textContent = fechaTexto(D.fecha[i]);
      p.entran.textContent = V.pieza ? nF.format(D.entran[posicion]) : "";
    }
  }

  function posicionEnResultado(i) {
    for (let x = 0; x < V.cuantos; x++) if (D.resultado[x] === i) return x;
    return -1;
  }

  function elegir(i, mostrarEnTabla) {
    V.elegido = i;
    if (mostrarEnTabla) {
      const x = posicionEnResultado(i);
      if (x >= 0) {
        const cuerpo = $("cuerpo");
        const y = x * V.fila;
        if (y < cuerpo.scrollTop || y + V.fila > cuerpo.scrollTop + cuerpo.clientHeight) {
          cuerpo.scrollTop = Math.max(0, y - cuerpo.clientHeight / 2);
        }
      }
    }
    pintarTabla();
    pintarGrafico();
    pintarDetalle();
  }

  function moverConTeclas(e) {
    if (!V.cuantos) return;
    const ahora = posicionEnResultado(V.elegido);
    const visibles = Math.max(1, Math.floor($("cuerpo").clientHeight / V.fila));
    const destinos = {
      ArrowDown: ahora + 1,
      ArrowUp: ahora - 1,
      PageDown: ahora + visibles,
      PageUp: ahora - visibles,
      Home: 0,
      End: V.cuantos - 1,
    };
    if (!(e.key in destinos)) return;
    e.preventDefault();
    const x = Math.max(0, Math.min(V.cuantos - 1, ahora < 0 ? 0 : destinos[e.key]));
    elegir(D.resultado[x], true);
  }

  // ----------------------------------------------------------------------------------------------- el detalle

  function pintarDetalle() {
    const i = V.elegido;
    const dibujo = $("detalle-dibujo");
    const datos = $("detalle-datos");
    if (i < 0) {
      $("detalle-titulo").textContent = "Elegí un recorte";
      $("detalle-nota").textContent = "Tocalo en la tabla o en el gráfico y acá lo ves a escala, con la pieza adentro si buscás una.";
      dibujo.innerHTML = "";
      datos.innerHTML = "";
      $("detalle-acciones").hidden = true;
      return;
    }
    const placa = D.placas[D.placa[i]];
    const largo = D.largo[i];
    const ancho = D.ancho[i];
    const cuantas = V.pieza ? cuantasEntran(i) : 0;
    const forma = textoDeForma(i);
    $("detalle-titulo").textContent = `S${D.numero[i]} · ${medida(largo, ancho)} mm${forma ? `, ${forma}` : ""}`;
    const filasDeDatos = [
      ["Placa", escapar(placa.nombre)],
      ["Medida", `${escapar(medida(largo, ancho))} mm${forma ? ` (lo que ocupa; es ${forma})` : ""}`],
      ["Superficie", metros2(D.area[i])],
      ["Veta", NOMBRE_VETA[D.veta[i]]],
      ["Guardado", fechaTexto(D.fecha[i])],
    ];
    if (placa.espesorMm != null) filasDeDatos.splice(1, 0, ["Espesor", `${escapar(mm(placa.espesorMm))} mm`]);
    if (placa.marca) filasDeDatos.splice(1, 0, ["Marca", escapar(placa.marca)]);
    if (V.pieza) {
      filasDeDatos.push([
        "Entran",
        cuantas
          ? `${nF.format(cuantas)} pieza${cuantas === 1 ? "" : "s"} de ${escapar(medida(F.largo, F.ancho))} mm`
          : `Ninguna pieza de ${escapar(medida(F.largo, F.ancho))} mm`,
      ]);
    }
    datos.innerHTML = filasDeDatos.map(([t, v]) => `<dt>${t}</dt><dd>${v}</dd>`).join("");
    dibujo.innerHTML = dibujoDelRecorte(i, placa, cuantas);
    $("detalle-nota").textContent = placa.formato
      ? `En gris punteado, la plancha entera (${medida(placa.formato[0] / UM_POR_MM, placa.formato[1] / UM_POR_MM)} mm), a la misma escala.`
      : "";
    $("detalle-acciones").hidden = false;
    $("copiado").textContent = "";
  }

  /* El recorte a escala, en la esquina de una plancha entera de su placa (si el catálogo la dice), con sus cotas, la
     veta en líneas finas y, si se busca una pieza, las que entran en filas y columnas. */
  function dibujoDelRecorte(i, placa, cuantas) {
    const W = 360;
    const H = 240;
    const margen = 28;
    const largo = D.largo[i];
    const ancho = D.ancho[i];
    const plancha = placa.formato ? [placa.formato[0] / UM_POR_MM, placa.formato[1] / UM_POR_MM] : [largo, ancho];
    const total = [Math.max(plancha[0], largo), Math.max(plancha[1], ancho)];
    const escala = Math.min((W - 2 * margen) / total[0], (H - 2 * margen) / total[1]);
    const x0 = margen;
    const y1 = H - margen;
    const partes = [];
    partes.push(`<defs><pattern id="veta-l" width="6" height="6" patternUnits="userSpaceOnUse"><path d="M0 5.5H6" style="stroke:var(--veta)" stroke-width="1"/></pattern><pattern id="veta-a" width="6" height="6" patternUnits="userSpaceOnUse"><path d="M5.5 0V6" style="stroke:var(--veta)" stroke-width="1"/></pattern></defs>`);
    if (placa.formato) {
      partes.push(
        `<rect x="${x0}" y="${y1 - plancha[1] * escala}" width="${plancha[0] * escala}" height="${plancha[1] * escala}" style="fill:none;stroke:var(--plancha)" stroke-dasharray="4 3"/>`,
      );
    }
    const w = largo * escala;
    const h = ancho * escala;
    const relleno = D.veta[i] === 1 ? "url(#veta-l)" : "url(#veta-a)";
    partes.push(figura(i, x0, y1, escala, 'style="fill:var(--recorte)"'));
    if (D.veta[i]) partes.push(figura(i, x0, y1, escala, `fill="${relleno}"`));
    if (cuantas) partes.push(piezasAdentro(i, x0, y1, escala));
    partes.push(figura(i, x0, y1, escala, 'style="fill:none;stroke:var(--recorte-borde)" stroke-width="1.5"'));
    // cotas: el largo abajo y el ancho a la izquierda
    partes.push(
      `<g style="fill:var(--texto-2)" font-size="11" font-family="IBM Plex Mono, Menlo, monospace">` +
        `<text x="${x0 + w / 2}" y="${y1 + 16}" text-anchor="middle">${escapar(mm(largo))}</text>` +
        `<text x="${x0 - 8}" y="${y1 - h / 2}" text-anchor="middle" transform="rotate(-90 ${x0 - 8} ${y1 - h / 2})">${escapar(mm(ancho))}</text>` +
        `</g>`,
    );
    return partes.join("");
  }

  /* El recorte: su rectángulo o, si tiene forma, su polígono (con Y para arriba, como en el taller). */
  function figura(i, x0, y1, escala, atributos) {
    const f = D.forma[i];
    if (!f) {
      const w = D.largo[i] * escala;
      const h = D.ancho[i] * escala;
      return `<rect x="${x0}" y="${y1 - h}" width="${w}" height="${h}" ${atributos}/>`;
    }
    const d = f.puntos
      .map(([x, y], k) => `${k ? "L" : "M"}${(x0 + x * escala).toFixed(2)} ${(y1 - y * escala).toFixed(2)}`)
      .join("");
    return `<path d="${d}Z" ${atributos}/>`;
  }

  function pieza(x, y, w, h) {
    return `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${w.toFixed(2)}" height="${h.toFixed(2)}" style="fill:var(--pieza);stroke:var(--pieza-borde)" fill-opacity="0.55" stroke-width="0.75"/>`;
  }

  /* En un retazo con forma, las piezas de la manera que más entran: cada parte en filas y columnas desde su esquina. */
  function piezasEnForma(i, x0, y1, escala) {
    const partes = [];
    let dibujadas = 0;
    for (const { r, girada } of llenarForma(i).partes) {
      const pl = girada ? F.ancho : F.largo;
      const pa = girada ? F.largo : F.ancho;
      const columnas = Math.floor((r[2] - r[0] + F.separacion) / (pl + F.separacion));
      const filasDe = Math.floor((r[3] - r[1] + F.separacion) / (pa + F.separacion));
      for (let f = 0; f < filasDe && dibujadas < DIBUJO_MAXIMO_DE_PIEZAS; f++) {
        for (let c = 0; c < columnas && dibujadas < DIBUJO_MAXIMO_DE_PIEZAS; c++) {
          const x = x0 + (r[0] + c * (pl + F.separacion)) * escala;
          const y = y1 - (r[1] + (f + 1) * pa + f * F.separacion) * escala;
          partes.push(pieza(x, y, pl * escala, pa * escala));
          dibujadas++;
        }
      }
    }
    return partes.join("");
  }

  function piezasAdentro(i, x0, y1, escala) {
    if (D.forma[i]) return piezasEnForma(i, x0, y1, escala);
    const v = D.veta[i];
    const derecha = enUnLado(D.largo[i], F.largo) * enUnLado(D.ancho[i], F.ancho);
    const girada = enUnLado(D.largo[i], F.ancho) * enUnLado(D.ancho[i], F.largo);
    let usarDerecha = derecha >= girada;
    if (F.respetarVeta && v === 1) usarDerecha = true;
    if (F.respetarVeta && v === 2) usarDerecha = false;
    const pl = usarDerecha ? F.largo : F.ancho;
    const pa = usarDerecha ? F.ancho : F.largo;
    const columnas = enUnLado(D.largo[i], pl);
    const filasDe = enUnLado(D.ancho[i], pa);
    const partes = [];
    let dibujadas = 0;
    for (let f = 0; f < filasDe && dibujadas < DIBUJO_MAXIMO_DE_PIEZAS; f++) {
      for (let c = 0; c < columnas && dibujadas < DIBUJO_MAXIMO_DE_PIEZAS; c++) {
        const x = x0 + (F.margen + c * (pl + F.separacion)) * escala;
        const y = y1 - (F.margen + (f + 1) * pa + f * F.separacion) * escala;
        partes.push(
          `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${(pl * escala).toFixed(2)}" height="${(pa * escala).toFixed(2)}" style="fill:var(--pieza);stroke:var(--pieza-borde)" fill-opacity="0.55" stroke-width="0.75"/>`,
        );
        dibujadas++;
      }
    }
    return partes.join("");
  }

  async function copiarNumero() {
    if (V.elegido < 0) return;
    const texto = `S${D.numero[V.elegido]}`;
    try {
      await navigator.clipboard.writeText(texto);
      $("copiado").textContent = `Copié ${texto}`;
    } catch (error) {
      $("copiado").textContent = `El número es ${texto}`;
    }
  }

  // ----------------------------------------------------------------------------------------------- el tema

  function configurarTema() {
    const boton = $("tema");
    const oscuroDelSistema = window.matchMedia("(prefers-color-scheme: dark)");
    const esOscuro = () => {
      const elegido = document.documentElement.getAttribute("data-theme");
      return elegido ? elegido === "dark" : oscuroDelSistema.matches;
    };
    const rotular = () => boton.setAttribute("aria-label", esOscuro() ? "Pasar al tema claro" : "Pasar al tema oscuro");
    const repintar = () => {
      rotular();
      if (G.ctx) {
        pintarFondoDelGrafico();
        pintarGrafico();
      }
    };
    boton.addEventListener("click", () => {
      const nuevo = esOscuro() ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", nuevo);
      try {
        localStorage.setItem("sobrantes-tema", nuevo);
      } catch (error) {
        /* sin almacenamiento: el tema vale hasta cerrar la página */
      }
      repintar();
    });
    oscuroDelSistema.addEventListener("change", repintar);
    rotular();
  }

  document.addEventListener("DOMContentLoaded", () => {
    conectarGrafico();
    iniciar();
  });
})();

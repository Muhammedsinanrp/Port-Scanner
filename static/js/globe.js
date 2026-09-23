/**
 * Dynamic Interactive 3D Cyber Globe Engine
 * Powered by Three.js
 */

let scene, camera, renderer, globeGroup;
let particlesMesh, linesMesh, targetBeacons = [];
let scanWaveMesh, scanRingMesh;
let isScanning3D = false;
let mouseX = 0, mouseY = 0;
let targetRotationX = 0, targetRotationY = 0;

function init3DGlobe() {
    const container = document.getElementById("globe-3d-canvas");
    if (!container || typeof THREE === "undefined") return;

    const width = container.clientWidth || 380;
    const height = container.clientHeight || 380;

    // 1. Scene & Camera
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 250;

    // 2. Renderer
    renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // 3. Dot-Matrix Cyber Sphere (Latitude & Longitude Points)
    const particleCount = 1800;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    const radius = 80;
    const colorCyan = new THREE.Color(0x38bdf8);
    const colorIndigo = new THREE.Color(0x818cf8);

    for (let i = 0; i < particleCount; i++) {
        // Fibonacci sphere distribution for uniform spherical mesh
        const phi = Math.acos(-1 + (2 * i) / particleCount);
        const theta = Math.sqrt(particleCount * Math.PI) * phi;

        const x = radius * Math.cos(theta) * Math.sin(phi);
        const y = radius * Math.sin(theta) * Math.sin(phi);
        const z = radius * Math.cos(phi);

        positions[i * 3] = x;
        positions[i * 3 + 1] = y;
        positions[i * 3 + 2] = z;

        // Gradient coloring
        const lerpFactor = (y + radius) / (2 * radius);
        const c = colorCyan.clone().lerp(colorIndigo, lerpFactor);
        colors[i * 3] = c.r;
        colors[i * 3 + 1] = c.g;
        colors[i * 3 + 2] = c.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const particleMaterial = new THREE.PointsMaterial({
        size: 2.2,
        vertexColors: true,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending,
    });

    particlesMesh = new THREE.Points(geometry, particleMaterial);
    globeGroup.add(particlesMesh);

    // 4. Inner Glowing Wireframe Sphere
    const innerGeo = new THREE.IcosahedronGeometry(radius * 0.98, 2);
    const innerMat = new THREE.MeshBasicMaterial({
        color: 0x0284c7,
        wireframe: true,
        transparent: true,
        opacity: 0.12,
    });
    const innerSphere = new THREE.Mesh(innerGeo, innerMat);
    globeGroup.add(innerSphere);

    // 5. Outer Orbital Ring
    const ringGeo = new THREE.RingGeometry(radius * 1.25, radius * 1.27, 64);
    const ringMat = new THREE.MeshBasicMaterial({
        color: 0x38bdf8,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.25,
    });
    scanRingMesh = new THREE.Mesh(ringGeo, ringMat);
    scanRingMesh.rotation.x = Math.PI / 2.3;
    globeGroup.add(scanRingMesh);

    // 6. Laser Scan Wave (Active during scanning)
    const waveGeo = new THREE.SphereGeometry(radius * 1.05, 32, 16);
    const waveMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        wireframe: true,
        transparent: true,
        opacity: 0.0,
    });
    scanWaveMesh = new THREE.Mesh(waveGeo, waveMat);
    globeGroup.add(scanWaveMesh);

    // 7. Interactive Mouse Tracking & Dragging
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };

    container.addEventListener('mousedown', (e) => {
        isDragging = true;
        previousMousePosition = { x: e.clientX, y: e.clientY };
    });

    window.addEventListener('mouseup', () => { isDragging = false; });

    container.addEventListener('mousemove', (e) => {
        if (!isDragging) {
            const rect = container.getBoundingClientRect();
            mouseX = ((e.clientX - rect.left) / width - 0.5) * 0.5;
            mouseY = ((e.clientY - rect.top) / height - 0.5) * 0.5;
            return;
        }

        const deltaX = e.clientX - previousMousePosition.x;
        const deltaY = e.clientY - previousMousePosition.y;

        globeGroup.rotation.y += deltaX * 0.01;
        globeGroup.rotation.x += deltaY * 0.01;

        previousMousePosition = { x: e.clientX, y: e.clientY };
    });

    // Touch support for mobile devices
    container.addEventListener('touchmove', (e) => {
        if (e.touches.length > 0) {
            const touch = e.touches[0];
            const rect = container.getBoundingClientRect();
            mouseX = ((touch.clientX - rect.left) / width - 0.5) * 0.5;
            mouseY = ((touch.clientY - rect.top) / height - 0.5) * 0.5;
        }
    }, { passive: true });

    // Handle Resize
    window.addEventListener('resize', onWindowResize);

    // Initial Beacons
    addRandomNodes();

    // Start Animation Loop
    animate();
}

function addRandomNodes() {
    const nodeCoords = [
        { lat: 37.77, lon: -122.41 }, // US West
        { lat: 40.71, lon: -74.00 },  // US East
        { lat: 51.50, lon: -0.12 },   // London
        { lat: 35.67, lon: 139.65 },  // Tokyo
        { lat: 1.35, lon: 103.81 },   // Singapore
        { lat: 19.07, lon: 72.87 },   // Mumbai
        { lat: 52.52, lon: 13.40 },   // Berlin
    ];

    nodeCoords.forEach(c => createBeacon(c.lat, c.lon));
}

function latLonToVector3(lat, lon, radius) {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lon + 180) * (Math.PI / 180);

    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = (radius * Math.sin(phi) * Math.sin(theta));
    const y = (radius * Math.cos(phi));

    return new THREE.Vector3(x, y, z);
}

function createBeacon(lat, lon, isTarget = false) {
    const pos = latLonToVector3(lat, lon, 80);
    
    // Beacon Dot
    const dotGeo = new THREE.SphereGeometry(isTarget ? 3.0 : 1.8, 12, 12);
    const dotMat = new THREE.MeshBasicMaterial({
        color: isTarget ? 0xef4444 : 0x10b981,
    });
    const dot = new THREE.Mesh(dotGeo, dotMat);
    dot.position.copy(pos);
    globeGroup.add(dot);

    // Glowing Pulse Ring around Beacon
    const haloGeo = new THREE.RingGeometry(2.5, 4.5, 16);
    const haloMat = new THREE.MeshBasicMaterial({
        color: isTarget ? 0xef4444 : 0x10b981,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.7,
    });
    const halo = new THREE.Mesh(haloGeo, haloMat);
    halo.position.copy(pos);
    halo.lookAt(0, 0, 0);
    globeGroup.add(halo);

    targetBeacons.push({ dot, halo, scale: 1.0 });
}

function triggerScan3DAnimation(active) {
    isScanning3D = active;
    if (scanWaveMesh) {
        scanWaveMesh.material.opacity = active ? 0.35 : 0.0;
    }
}

function triggerPortDiscoveredPulse() {
    // Pulse effect across globe
    if (scanWaveMesh) {
        scanWaveMesh.scale.set(1.2, 1.2, 1.2);
        scanWaveMesh.material.opacity = 0.6;
        setTimeout(() => {
            scanWaveMesh.scale.set(1.05, 1.05, 1.05);
            scanWaveMesh.material.opacity = isScanning3D ? 0.35 : 0.0;
        }, 300);
    }
}

function onWindowResize() {
    const container = document.getElementById("globe-3d-canvas");
    if (!container || !renderer || !camera) return;

    const width = container.clientWidth;
    const height = container.clientHeight;
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height);
}

let clock = new THREE.Clock();

function animate() {
    requestAnimationFrame(animate);

    const delta = clock.getDelta();
    const time = clock.getElapsedTime();

    if (globeGroup) {
        // Smooth rotation
        const baseSpeed = isScanning3D ? 0.015 : 0.003;
        globeGroup.rotation.y += baseSpeed;
        globeGroup.rotation.x += (mouseY - globeGroup.rotation.x * 0.1) * 0.03;

        // Subtle floating tilt
        globeGroup.rotation.z = Math.sin(time * 0.5) * 0.05;
    }

    // Pulse beacons
    targetBeacons.forEach(b => {
        b.scale += delta * 1.5;
        if (b.scale > 2.2) b.scale = 1.0;
        b.halo.scale.set(b.scale, b.scale, b.scale);
        b.halo.material.opacity = 0.8 - (b.scale - 1.0) / 1.2 * 0.8;
    });

    // Orbital ring spin
    if (scanRingMesh) {
        scanRingMesh.rotation.z += 0.005;
    }

    // Laser scan wave animation
    if (isScanning3D && scanWaveMesh) {
        scanWaveMesh.rotation.y += 0.03;
        scanWaveMesh.rotation.x = Math.sin(time * 3) * 0.3;
    }

    renderer.render(scene, camera);
}

// Initialize when DOM ready
document.addEventListener("DOMContentLoaded", () => {
    init3DGlobe();
});

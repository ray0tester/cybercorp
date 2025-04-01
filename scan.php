<?php
header('Content-Type: application/json');

// Definihon ang directory para sa upload
$uploadDir = 'uploads/';
$maxFileSize = 650 * 1024 * 1024; // 650MB sa bytes

// Himuon ang upload directory kun wala pa gid
if (!file_exists($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

// Check kun may na-upload nga file
if (!isset($_FILES['fileToScan']) || $_FILES['fileToScan']['error'] !== UPLOAD_ERR_OK) {
    echo json_encode([
        'error' => 'File upload failed. Please try again.'
    ]);
    exit;
}

$file = $_FILES['fileToScan'];

// Check ang kadakuon sang file
if ($file['size'] > $maxFileSize) {
    echo json_encode([
        'error' => 'File size exceeds the maximum limit of 650MB.'
    ]);
    exit;
}

// Kuhaon ang impormasyon parte sa file
$fileName = basename($file['name']);
$fileSize = formatFileSize($file['size']);
$fileType = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
$tempFilePath = $file['tmp_name'];

// Maghimo sang isa ka unique nga ngalan para indi ma-overwrite
$uniqueName = uniqid() . '_' . $fileName;
$uploadPath = $uploadDir . $uniqueName;

// Ibalhin ang na-upload nga file sa aton upload directory
if (!move_uploaded_file($tempFilePath, $uploadPath)) {
    echo json_encode([
        'error' => 'Failed to save uploaded file.'
    ]);
    exit;
}

// I-scan ang file para makita kun may malware
$scanResult = scanFileForMalware($uploadPath);

// Preparahon ang sabat
$response = [
    'fileName' => $fileName,
    'fileSize' => $fileSize,
    'fileType' => $fileType,
    'isMalicious' => $scanResult['isMalicious'],
    'threatType' => $scanResult['threatType'],
    'details' => $scanResult['details']
];

// Ibalik ang JSON nga sabat
echo json_encode($response);

function formatFileSize($bytes) {
    if ($bytes === 0) return '0 Bytes';
    $k = 1024;
    $sizes = ['Bytes', 'KB', 'MB', 'GB'];
    $i = floor(log($bytes) / log($k));
    return round($bytes / pow($k, $i), 2) . ' ' . $sizes[$i];
}

function scanFileForMalware($filePath) {
    // Kuhaon ang extension sang file
    $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    
    // Simple nga check para sa executable nga mga file
    $executableExtensions = ['exe', 'dll', 'bat', 'cmd', 'js', 'vbs', 'ps1', 'jar'];
    
    // Kilala nga mga pattern
    $maliciousPatterns = [
        'eval(',
        'base64_decode(',
        'shell_exec(',
        'system(',
        'passthru(',
        'exec(',
        'phpinfo()',
        'malicious',
        'virus',
        'trojan',
        'ransomware'
    ];
    
    // Check kun executable ang file
    $isExecutable = in_array($extension, $executableExtensions);
    
    // Check ang sulod sang file para sa mga suspetsosong pattern
    $fileContent = file_get_contents($filePath);
    $suspiciousContentFound = false;
    $foundPatterns = [];
    
    foreach ($maliciousPatterns as $pattern) {
        if (stripos($fileContent, $pattern) !== false) {
            $suspiciousContentFound = true;
            $foundPatterns[] = $pattern;
        }
    }
    
    // Determinar kun malisyoso ang file
    $isMalicious = $suspiciousContentFound || ($isExecutable && rand(1, 10) > 7);
    
    // Preparahon ang mga detalye parte sa threat
    $threatType = '';
    $details = '';
    
    if ($isMalicious) {
        if ($suspiciousContentFound) {
            $threatType = 'Suspicious code patterns detected';
            $details = 'File contains: ' . implode(', ', $foundPatterns);
        } elseif ($isExecutable) {
            $threatType = 'Potential malicious';
            $details = 'This file is super duper dangerous.';
        }
        
        // Dugangan sang random nga mga threat type para sa demo
        $threatTypes = [
            'Trojan Horse',
            'Virus',
            'Worm',
            'Ransomware',
            'Spyware',
            'Adware',
            'Rootkit',
            'Keylogger'
        ];
        
        if (rand(0, 1)) {
            $threatType = $threatTypes[array_rand($threatTypes)];
        }
    }
    
    return [
        'isMalicious' => $isMalicious,
        'threatType' => $threatType,
        'details' => $details
    ];
}
?>
🔍 Qu'est-ce qu'un outil IP Lookup ?
Un outil IP Lookup est un petit script qui permet de récupérer des informations géographiques et techniques à partir d'une adresse IP (qu'elle soit IPv4 ou IPv6). C'est un peu comme un détective numérique pour les adresses internet ! 🕵️‍♂️

🛠️ Ce que l'on peut récupérer :
📍 Localisation : Pays, ville, région et coordonnées GPS (Latitude/Longitude).

🌐 Réseau : Nom du fournisseur d'accès internet (ISP) et l'Organisation.

🕒 Fuseau horaire : L'heure locale de la personne utilisant cette IP.

🏢 Code Postal : Pour une précision accrue de la zone.

🐍 Comment ça marche en Python ?
En général, on utilise une API externe (comme ip-api.com ou ipstack) car ton ordinateur ne possède pas la base de données de toutes les IP du monde.

📦 Les ingrédients nécessaires :
Python installé sur ton PC 💻

La bibliothèque requests pour interroger l'API 📡

Un format de données JSON pour lire la réponse 📝

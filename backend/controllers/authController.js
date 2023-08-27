const User = require('../models/User')
//Import du module JSON Web Token pour gérer les tokens d'authentification
const jwt = require("jsonwebtoken")
// Import du module bcrypt pour le hachage des mots de passe
const bcrypt = require('bcrypt')

// Fonction pour l'inscription d'un nouvel utilisateur
const register = async (req, res) => {
    // Un message de débogage, peut être retiré en production
    console.log('alaa')
    try {
          // Vérifie si des champs requis sont vides dans la requête
        const isEmpty = Object.values(req.body).some((v) => !v)
        if(isEmpty){
            // Lève une erreur si des champs sont vides
            throw new Error("Fill all fields!")
        }

        // Vérifie si un utilisateur avec le même nom d'utilisateur existe déjà
        const isExisting = await User.findOne({username: req.body.username})
        if(isExisting){
            // Affiche une erreur si l'utilisateur existe déjà
            throw new Error("Account is already registered")
        }

        console.log(req.body)

        // Hache le mot de passe avant de l'enregistrer dans la base de données
        const hashedPassword = await bcrypt.hash(req.body.password, 10)

        // Crée un nouvel utilisateur en utilisant les données de la requête et le mot de passe haché
        const newUser = await User.create({...req.body, password: hashedPassword})

        // Crée un payload pour le token JWT contenant l'ID de l'utilisateur et son nom d'utilisateur
        const payload = {id: newUser._id, username: newUser.username}

        // Supprime le champ "password" des données de l'utilisateur pour des raisons de sécurité
        const {password, ...others} = newUser._doc

        // Génère un token JWT avec le payload et la clé secrète
        const token = jwt.sign(payload, process.env.JWT_SECRET)

        // Renvoie une réponse avec le token et d'autres données de l'utilisateur
        return res.status(201).json({token, others})
    } catch (error) {
         // En cas d'erreur, renvoie une réponse avec le message d'erreur et un code d'erreur 500 (erreur serveur)
        return res.status(500).json(error.message)
    }
}

// Fonction pour la connexion d'un utilisateur existant
const login = async (req, res) => {
    try {
        const isEmpty = Object.values(req.body).some((v) => v ==='')
        if(isEmpty){
            // Lève une erreur si des champs sont vides
            throw new Error("Fill all fields!")
        }

        // Recherche un utilisateur avec l'adresse e-mail fournie
        const user = await User.findOne({email: req.body.email})
        if(!user){
            // Affiche une erreur si l'utilisateur n'est pas trouvé
            throw new Error("Wrong credentials")
        }

        // Compare le mot de passe fourni avec le mot de passe haché enregistré dans la base de données
        const comparePass = await bcrypt.compare(req.body.password, user.password)
        if(!comparePass){
            // Lève une erreur si les identifiants sont incorrects
            throw new Error("Wrong credentials")
        }
        // Crée un payload pour le token JWT contenant l'ID de l'utilisateur et son nom d'utilisateur
        const payload = {id: user._id, username: user.username}
        // Supprime le champ "password" des données de l'utilisateur pour des raisons de sécurité
        const {password, ...others} = user._doc
        // Génère un token JWT avec le payload et la clé secrète
        const token = jwt.sign(payload, process.env.JWT_SECRET)
        // Renvoie une réponse avec le token et d'autres données de l'utilisateur
        return res.status(200).json({token, others})
    } catch (error) {
        // En cas d'erreur, renvoie une réponse avec le message d'erreur et un code d'erreur 500 (erreur coté serveur)
        return res.status(500).json(error.message)
    }
}

// Exporte les fonctions register et login pour les rendre accessibles depuis d'autres modules
module.exports = { register, login}
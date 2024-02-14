const express = require('express');
const app = express();
const cors = require('cors');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY);
const port = process.env.PORT || 5000;


//middleware
app.use(cors());
app.use(express.json())

//verifyJWT
const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: 'unauthorized access' })
    }
    const token = authorization.split(' ')[1];
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ error: true, message: 'unauthorized access' })
        }
        req.decoded = decoded;
        next();
    });
}

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.cg7riyw.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        //await client.connect();

        const menuCollection = client.db('bistroDB').collection('menu');
        const usersCollection = client.db('bistroDB').collection('users');
        const reviewCollection = client.db('bistroDB').collection('reviews');
        const cartCollection = client.db('bistroDB').collection('carts');
        const paymentCollection = client.db('bistroDB').collection('payments');

        //JWT

        app.post('/jwt', (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
            res.send({ token })
        })

        //warning::: use verifyJWT before using verifyAdmin
        //verifyAdmin middleware
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email }
            const user = await usersCollection.findOne(query);
            if (user?.role !== 'admin') {
                return res.status(403).send({ error: true, message: 'forbidden access' })
            }
            next()
        }

        //usersCollection api

        /**
         * security layer:
         * 1.do not show admin links to those who should not see the links
         * 2.use jwt token:verifyJWT
         * 3.use verify admin
         * 3.check admin
         * 4.make admin only route
         */
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result)
        })
        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'User already exist' })
            }
            const result = await usersCollection.insertOne(user);
            res.send(result);
        })

        /**
         * security layer:
         * 1.verifyJWT
         * 2.email same 
         * 3.check admin
         * 4
         */
        app.get('/users/admin/:email', verifyJWT, async (req, res) => {
            const email = req.params.email;
            if (req.decoded.email !== email) {
                return res.send({ admin: false })
            }
            const query = { email: email }
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === 'admin' };
            res.send(result)
        })

        app.patch('/users/admin/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) }
            const updateDoc = {
                $set: {
                    role: 'admin'
                }
            }
            const result = await usersCollection.updateOne(filter, updateDoc)
            res.send(result)
        })


        //menuCollection api
        app.get('/menu', async (req, res) => {
            const result = await menuCollection.find().toArray();
            res.send(result)

        })

        app.post('/menu', async (req, res) => {
            const newItem = req.body;
            const result = await menuCollection.insertOne(newItem);
            res.send(result);
        })


        app.delete('/menu/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: id };
            const result = await menuCollection.deleteOne(query);
            res.send(result);
        })

        //reviewsCollection api
        app.get('/reviews', async (req, res) => {
            const result = await reviewCollection.find().toArray();
            res.send(result)

        })

        //cartCollection api
        app.get('/carts', verifyJWT, async (req, res) => {
            const email = req.query.email;
            if (!email) {
                res.send([])
            }
            const decodedEmail = req.decoded.email;
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'Forbidden access' })
            }
            const query = { email: email };
            const result = await cartCollection.find(query).toArray();
            res.send(result)


        })
        app.post('/carts', async (req, res) => {

            const result = await cartCollection.insertOne(req.body);
            res.send(result)

        })
        app.delete('/carts/:id', async (req, res) => {
            const { id } = req.params;
            const query = { _id: new ObjectId(id) }
            const result = await cartCollection.deleteOne(query);
            res.send(result)

        })

        //create payment intent
        app.post('/create-payment-intent', verifyJWT, async (req, res) => {
            const { price } = req.body;
            const priceToCent = price * 100;
            const amount = parseInt(priceToCent);

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: "usd",
                payment_method_types: ['card']
            })
            res.send({
                clientSecret: paymentIntent.client_secret
            })
        })

        //payment related api
        app.post('/payments', verifyJWT, async (req, res) => {
            const payment = req.body;
            const insertResult = await paymentCollection.insertOne(payment);

            const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } };

            const deleteResult = await cartCollection.deleteMany(query);
            res.send({ insertResult, deleteResult })
        })

        //stats related api
        app.get('/admin-stats', verifyJWT, verifyAdmin, async (req, res) => {
            const users = await usersCollection.estimatedDocumentCount();
            const products = await menuCollection.estimatedDocumentCount();
            const orders = await paymentCollection.estimatedDocumentCount();

            //best way to get sum of the price field is to use group & sum operator 
            /*
            const result = await paymentCollection.aggregate([
                {
                    $group: {
                        _id: null,
                        totalAmount: { $sum: '$price' }
                    }
                }
            ]).toArray();

            const revenue = result[0].totalAmount;
            */
            const payments = await paymentCollection.find().toArray();

            const revenue = payments.reduce((sum, payment) => sum + payment.price, 0);


            res.send({ revenue, users, products, orders })
        })

        /**
         * Bangla System(second best)
         * ==========================
         * 1.load all payments
         * 2.for each payment,get the menuItems array
         * 3.for each item in the menuItems array get the menuItem from the menu collection.
         * 4.put them in an array:allOrderedItems
         * 5.separate  allOrderedItems by category using filter
         * 6.get the quantity by length
         * 7 for each category use reduce to get the total amount spent on this category
         *  */
        app.get('/order-stats', verifyJWT, verifyAdmin, async (req, res) => {
            const pipeline = [
                {
                    $unwind: '$menuItems',
                },
                {
                    $lookup: {
                        from: 'menu',
                        localField: 'menuItems',
                        foreignField: '_id',
                        as: 'menuItemDetails',
                    },
                },
                {
                    $unwind: '$menuItemDetails',
                },
                {
                    $group: {
                        _id: '$menuItemDetails.category',
                        itemCount: { $sum: 1 },
                        price: { $sum: '$menuItemDetails.price' },
                    },
                },
                {
                    $project: {
                        category: '$_id',
                        itemCount: 1,
                        price: { $round: ['$price', 2] }, // Round the price to two decimal places
                        _id: 0,
                    },
                },
            ];
            const result = await paymentCollection.aggregate(pipeline).toArray();
            res.send(result);
        })



        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        //await client.close();
    }
}
run().catch(console.dir);










app.get('/', (req, res) => {
    res.send('Boss server running...')
})

app.listen(port, () => {
    console.log(`Boss server running on port ${port}`)
})
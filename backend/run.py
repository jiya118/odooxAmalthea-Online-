from app import app, db

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("🚀 Starting Expense Manager...")
    print("📱 Access the application at: http://localhost:5000")
    app.run(debug=True, port=5000)
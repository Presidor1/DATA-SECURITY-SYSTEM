# ... [all your unchanged code above] ...

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        print("DOWNLOAD ERROR:", traceback.format_exc())
        flash("File could not be downloaded.", "danger")
        return redirect(url_for('my_uploads'))

# ✅ NEWLY ADDED ROUTE FOR VIEWING FILES
@app.route('/view/<filename>')
def view_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print("VIEW FILE ERROR:", traceback.format_exc())
        flash("File could not be viewed.", "danger")
        return redirect(url_for('my_uploads'))

# ========== Error Handler ========= #
@app.errorhandler(500)
def internal_error(error):
    print("INTERNAL SERVER ERROR:", traceback.format_exc())
    return render_template('500.html'), 500

# ========== Start Server ========= #
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)

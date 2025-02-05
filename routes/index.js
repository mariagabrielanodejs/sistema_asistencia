var express = require('express');
var router = express.Router();
const pool = require('../config/database');
const bcrypt = require('bcrypt');
const auth = require('../middleware/auth');
const XLSX = require('xlsx');
const cron = require('node-cron');
const { createObjectCsvStringifier } = require('csv-writer');
const PDFDocument = require('pdfkit');

const fecha = () => {
  let date = new Date().toLocaleString("en-US", { timeZone: "America/Caracas" });
  date = new Date(date);
  let hours = date.getHours();
  let minutes = date.getMinutes();
  hours = hours % 12;
  hours = hours ? hours : 12;
  minutes = minutes.toString().padStart(2, '0');
  let day = date.getDate().toString().padStart(2, '0');
  let month = (date.getMonth() + 1).toString().padStart(2, '0');
  let year = date.getFullYear();
  let dateTime = `${day}-${month}-${year}`;
  return `${dateTime}`;
};

const hora = () => {
  let date = new Date().toLocaleString("en-US", { timeZone: "America/Caracas" });
  date = new Date(date);
  let hours = date.getHours();
  let minutes = date.getMinutes();
  hours = hours % 12;
  hours = hours ? hours : 12;
  minutes = minutes.toString().padStart(2, '0');
  let ampm = date.getHours() >= 12 ? 'pm' : 'am';
  let dateTime = `${hours}:${minutes} ${ampm}`;
  return `${dateTime}`;
}



cron.schedule('0 16 * * *', async () => {
  try {
    const fechaHoy = fecha();
    const horaHoy = hora();
    const [result] = await pool.query(`
      INSERT INTO asistencia (id_usuario, fecha, hora, estado, rol)
      SELECT u.id_usuario, ?, ?, 'Ausente', r.nombre_rol
      FROM usuario u
      INNER JOIN rol r ON u.id_rol = r.id_rol
      WHERE NOT EXISTS (
        SELECT 1 FROM asistencia a 
        WHERE a.id_usuario = u.id_usuario 
        AND a.fecha = ?
      )
    `, [fechaHoy, horaHoy, fechaHoy]);
    console.log(`Usuarios marcados como ausentes: ${result.affectedRows}`);
  } catch (error) {
    console.error('Error en cron job:', error);
  }
}, {
  timezone: 'America/Caracas'
});


router.get('/', auth.isGuest, (req, res) => {
  res.render('index', {
    result: false
  });
});

router.get('/visitante', auth.isAuthenticated, (req, res) => {
  res.render('visitante', {
    id_usuario: req.session.userId,
    username: req.session.username,
    error: req.query.error,
    info: req.query.info
  });
});



router.get('/admin_login', (req, res) => {
  res.render('admin_login', {
    result: false
  });
});

router.post('/admin_login', async (req, res) => {
  try {
    const { usuario, contrasena } = req.body;

    const [users] = await pool.execute(
      'SELECT id_usuario, username, contraseña, id_rol FROM usuario WHERE username = ?',
      [usuario]
    );
    if (users.length === 0) {
      return res.render('admin_login', {
        result: true,
        message: 'Contraseña o usuario incorrectos.'
      });
    }
    const user = users[0];
    const match = await bcrypt.compare(contrasena, user.contraseña);

    if (!match) {
      return res.render('admin_login', {
        result: true,
        message: 'Contraseña o usuario incorrectos.'
      });
    }

    if (user.id_rol !== 1) {
      return res.render('admin_login', {
        result: true,
        message: 'No tienes permisos para acceder a esta sección.'
      });
    }

    req.session.userId = user.id_usuario;
    req.session.username = user.username;
    req.session.rol = user.id_rol;
    res.redirect('/admin');
  } catch (error) {
    console.error('Error en login:', error);
    res.render('admin_login', {
      result: true,
      message: 'Error en el sistema, Intente más tarde.'
    });
  }
});


router.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/visitante?error=Error al cerrar sesión');
    }
    res.clearCookie('session_cookie');
    res.redirect('/');
  });
});


router.get('/logoutadmin', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/visitante?error=Error al cerrar sesión');
    }
    res.clearCookie('session_cookie');
    res.redirect('/admin_login');
  });
});


router.post('/login', async (req, res) => {
  try {
    const { usuario, contrasena } = req.body;

    const [users] = await pool.execute(
      'SELECT id_usuario, username, contraseña, id_rol FROM usuario WHERE username = ?',
      [usuario]
    );

    if (users.length === 0) {
      return res.render('index', {
        result: true,
        message: 'Contraseña o usuario incorrectos.'
      });
    }

    const user = users[0];
    const match = await bcrypt.compare(contrasena, user.contraseña);

    if (!match) {
      return res.render('index', {
        result: true,
        message: 'Contraseña o usuario incorrectos.'
      });
    }


    req.session.userId = user.id_usuario;
    req.session.username = user.username;
    req.session.rol = user.id_rol;

    res.redirect('/visitante');

  } catch (error) {
    console.error('Error en login:', error);
    res.render('index', {
      result: true,
      message: 'Error en el sistema, Intente más tarde.'
    });
  }
});


router.get('/visitante/asistencia/:id', auth.isAuthenticated, async (req, res) => {
  try {
    const fechaActual = fecha();
    const horaActual = hora();
    const { id } = req.params;
    const [asistencias] = await pool.execute(
      'SELECT * FROM asistencia WHERE id_usuario = ? AND fecha = ?',
      [id, fechaActual]
    );

    if (asistencias.length > 0) {
      return res.redirect('/visitante?error=Ya has registrado tu asistencia el día de hoy.');
    }

    await pool.execute(
      'INSERT INTO asistencia (id_usuario, fecha, hora, estado, rol) VALUES (?, ?, ?, "Asistente", ?)',
      [id, fechaActual, horaActual, req.session.rol]
    );
    res.redirect('/visitante?info=Asistencia registrada con éxito.');
  } catch (error) {
    console.error('Error en asistencia:', error);
    res.redirect('/visitante?error=Error en el sistema.');
  }
});



const getUsers = async () => {
  try {
    const [users] = await pool.query(`
          SELECT id_usuario, id_rol, username, nombre, apellido, cedula 
          FROM usuario
      `);
    return users;
  } catch (error) {
    throw error;
  }
};


const getAsistencias = async (fechaHoy) => {
  try {
    const [asistencias] = await pool.query(`
          SELECT u.nombre, u.apellido, a.fecha, a.hora, a.estado, u.cedula, r.nombre_rol as rol
          FROM asistencia a
          INNER JOIN usuario u ON a.id_usuario = u.id_usuario
          INNER JOIN rol r ON a.rol = r.id_rol 
          WHERE a.fecha = ? ORDER BY a.fecha
      `, [fechaHoy]);
    return asistencias;
  } catch (error) {
    throw error;
  }
};

const isAdmin = (req, res, next) => {
  if (req.session.userId && req.session.rol === 1) {

    return next();
  }
  res.redirect('/admin_login');
};

router.get('/admin', isAdmin, async (req, res) => {
  try {
    const users = await getUsers();
    res.render('admin', {
      users,
      error: req.query.error,
      success: req.query.success
    });
  } catch (error) {
    console.error('Error en admin:', error);
    res.render('error', {
      message: 'Error en el sistema'
    });
  }
});

router.get('/admin/asistencias/export/:name', isAdmin, async (req, res) => {
  try {
    const fechaHoy = req.params.name;
    const asistencias = await getAsistencias(fechaHoy);
    const wsData = [
      ["Nombre", "Apellido", "Cedula", "Fecha", "Hora", "Rol", "Estado"],
      ...asistencias.map(a => [a.nombre, a.apellido, a.cedula, a.fecha, a.hora || '--:--', a.rol, a.estado])
    ];

    const ws = XLSX.utils.aoa_to_sheet(wsData);

    // Crear libro de trabajo
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Asistencias");

    // Generar buffer
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // Enviar archivo
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="asistencias_${fechaHoy.replace(/\//g, '-')}.xlsx"`
    );
    res.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);

  } catch (error) {
    console.error('Error al exportar:', error);
    res.status(500).send('Error al generar el archivo');
  }
});

router.get('/admin/asistencias/export/csv/:name', isAdmin, async (req, res) => {
  try {
    const fechaHoy = req.params.name;
    const asistencias = await getAsistencias(fechaHoy);

    // Configurar el generador de CSV en memoria
    const csvStringifier = createObjectCsvStringifier({
      header: [
        { id: 'nombre', title: 'NOMBRE' },
        { id: 'apellido', title: 'APELLIDO' },
        { id: 'fecha', title: 'FECHA' },
        { id: 'hora', title: 'HORA' },
        { id: 'cedula', title: 'CEDULA' },
        { id: 'rol', title: 'ROL' },
        { id: 'estado', title: 'ESTADO' }
      ]
    });

    // Generar la cabecera y los registros
    const header = csvStringifier.getHeaderString();
    const records = csvStringifier.stringifyRecords(asistencias);
    const csvContent = header + records;

    // Configurar las cabeceras y enviar el CSV
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="asistencias_${fechaHoy}.csv"`);
    res.send(csvContent);

  } catch (error) {
    console.error('Error al exportar CSV:', error);
    res.status(500).send('Error al generar CSV');
  }
});

router.get('/admin/asistencias/export/pdf/:name', isAdmin, async (req, res) => {
  try {
    const fechaHoy = req.params.name;
    const asistencias = await getAsistencias(fechaHoy);

    // Crear el documento PDF y configurar el nombre del archivo
    const doc = new PDFDocument();
    const filename = `asistencias_${fechaHoy}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Encabezado del PDF
    doc
      .font('Helvetica-Bold')
      .fontSize(18)
      .text('Registro de Asistencias', { align: 'center' });
    doc.moveDown(0.5);
    doc
      .fontSize(12)
      .text(`Fecha: ${fechaHoy}`, { align: 'center' });
    doc.moveDown(2);

    // Configuración de la tabla
    const table = {
      headers: ['Nombre', 'Apellido', 'Fecha', 'Cédula', 'Rol', 'Hora', 'Estado'],
      // Convertir cada asistencia en un array con los campos deseados
      rows: asistencias.map(a => [
        a.nombre,
        a.apellido,
        a.fecha,
        a.cedula,
        a.rol,
        a.hora || '--:--',
        a.estado
      ])
    };

    // Configuración de dimensiones y posición de la tabla
    const tableWidth = 500;                           // ancho total de la tabla
    const pageWidth = doc.page.width;                 // ancho de la página
    const tableLeft = (pageWidth - tableWidth) / 2;     // centrar la tabla horizontalmente
    const tableTop = doc.y;                           // posición vertical inicial de la tabla
    const colCount = table.headers.length;
    const colWidth = tableWidth / colCount;           // ancho de cada columna
    const rowHeight = 20;                             // altura de cada fila

    // --- Dibujo de la fila de encabezados ---
    doc.font('Helvetica-Bold').fontSize(10);
    table.headers.forEach((header, colIndex) => {
      // Calcula la posición X de la celda
      const cellX = tableLeft + colIndex * colWidth;
      // Mide el ancho del texto
      const textWidth = doc.widthOfString(header);
      // Centra el texto dentro de la celda
      const textX = cellX + (colWidth - textWidth) / 2;
      // Se coloca el texto sin definir un ancho fijo para evitar el "wrap"
      doc.text(header, textX, tableTop + 5, { lineBreak: false });
    });

    // Número total de filas (incluye el encabezado)
    const totalRows = 1 + table.rows.length;

    // --- Dibujar los bordes horizontales ---
    for (let i = 0; i <= totalRows; i++) {
      const y = tableTop + i * rowHeight;
      doc
        .moveTo(tableLeft, y)
        .lineTo(tableLeft + tableWidth, y)
        .stroke();
    }

    // --- Dibujar los bordes verticales ---
    for (let i = 0; i <= colCount; i++) {
      const x = tableLeft + i * colWidth;
      doc
        .moveTo(x, tableTop)
        .lineTo(x, tableTop + totalRows * rowHeight)
        .stroke();
    }

    // --- Dibujar las filas de datos ---
    doc.font('Helvetica').fontSize(10);
    table.rows.forEach((row, rowIndex) => {
      row.forEach((cellText, colIndex) => {
        cellText = cellText.toString(); // Asegurarse de que sea string
        const cellX = tableLeft + colIndex * colWidth;
        const textWidth = doc.widthOfString(cellText);
        // Centrar el texto dentro de la celda calculando la posición X
        const textX = cellX + (colWidth - textWidth) / 2;
        // La posición Y se calcula según el número de fila (se salta la fila de encabezado)
        const textY = tableTop + (rowIndex + 1) * rowHeight + 5;
        // Escribe el texto sin forzar un ancho, evitando el salto de línea
        doc.text(cellText, textX, textY, { lineBreak: false });
      });
    });

    // Enviar el PDF generado al cliente
    doc.pipe(res);
    doc.end();

  } catch (error) {
    console.error('Error al exportar PDF:', error);
    res.status(500).send('Error al generar PDF');
  }
});

router.get('/admin/asistencias', isAdmin, async (req, res) => {
  try {
    const fechaHoy = fecha();
    const HoraHoy = hora();
    const asistencias = await getAsistencias(fechaHoy);
    res.render('asistencias', {
      asistencias,
      error: req.query.error,
      success: req.query.success,
      fecha: fechaHoy,
      hora: HoraHoy
    });
  } catch (error) {
    console.error('Error en asistencias:', error);
    res.render('error', {
      message: 'Error en el sistema'
    });
  }
});


router.get('/admin/asistencias/fecha', isAdmin, async (req, res) => {
  try {
    const fechaHoy = fecha();
    const asistencias = await getAsistencias(fechaHoy);
    res.render('asistenciasporfecha', {
      asistencias,
      error: req.query.error,
      success: req.query.success,
      fecha: fechaHoy,
    });
  } catch (error) {
    console.error('Error en asistencias:', error);
    res.render('error', {
      message: 'Error en el sistema'
    });
  }
});

router.post('/admin/asistencias/fecha', isAdmin, async (req, res) => {
  try {
    let { fecha } = req.body;
    fecha = fecha.replace(/\//g, '-').split('-').reverse().join('-');

    console.log(fecha)
    const asistencias = await getAsistencias(fecha);
    res.render('asistenciasporfecha', {
      asistencias,
      error: req.query.error,
      success: req.query.success,
      fecha: fecha,
    });
  } catch (error) {
    console.error('Error en asistencias:', error);
  }
});


router.get('/admin/users/:id', isAdmin, async (req, res) => {
  try {
    const [user] = await pool.query(
      'SELECT * FROM usuario WHERE id_usuario = ?',
      [req.params.id]
    );
    res.json(user[0]);
  } catch (error) {
    res.redirect('/admin/?error=Error al obtener al usuario');
  }
});


router.post('/admin/users/update', isAdmin, async (req, res) => {
  try {
    const { id_usuario, id_rol,  nombre, apellido, cedula, username, contrasena } = req.body;

    // Obtener los datos actuales del usuario
    const [userData] = await pool.execute(
      'SELECT cedula, username, contraseña FROM usuario WHERE id_usuario = ?',
      [id_usuario]
    );

    if (userData.length === 0) {
      return res.redirect('/admin/?error=Usuario no encontrado');
    }

    const currentUser = userData[0];

    // Verificar si la cédula ha cambiado
    if (cedula !== currentUser.cedula) {
      const [cedulaExists] = await pool.execute(
        'SELECT id_usuario FROM usuario WHERE cedula = ? AND id_usuario != ?',
        [cedula, id_usuario]
      );

      if (cedulaExists.length > 0) {
        return res.redirect('/admin/?error=La cédula ya está registrada por otro usuario.');
      }
    }

    if (username !== currentUser.username) {
      const [usernameExists] = await pool.execute(
        'SELECT id_usuario FROM usuario WHERE username = ? AND id_usuario != ?',
        [username, id_usuario]
      );

      if (usernameExists.length > 0) {
        return res.redirect('/admin/?error=El nombre de usuario ya está en uso.');
      }
    }

    // Si la contraseña está vacía, mantener la actual
    let newPassword = currentUser.contraseña;
    if (contrasena && contrasena.trim() !== '') {
      newPassword = await bcrypt.hash(contrasena, 10);
    }

    // Actualizar los datos
    await pool.execute(
      `UPDATE usuario SET 
          id_rol = ?,
          nombre = ?, 
          apellido = ?, 
          cedula = ?, 
          username = ?, 
          contraseña = ?  
      WHERE id_usuario = ?`,
      [id_rol, nombre, apellido, cedula, username, newPassword, id_usuario]
    );

    res.redirect('/admin?success=Usuario actualizado');
  } catch (error) {
    console.log(error);
    res.redirect('/admin?error=Error al actualizar usuario');
  }
});



router.get('/admin/users/delete/:id', isAdmin, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM usuario WHERE id_usuario = ?',
      [req.params.id]
    );
    res.redirect('/admin?success=Usuario eliminado');
  } catch (error) {
    res.redirect('/admin?error=Error al eliminar usuario');
  }
});


router.post('/admin/users/create', isAdmin, async (req, res) => {
  try {
    const { id_rol, nombre, apellido, cedula, username, contrasena } = req.body;
    const [users] = await pool.execute(
      'SELECT username FROM usuario WHERE username = ?',
      [username]
    );

    const [cedulas] = await pool.execute(
      'SELECT cedula FROM usuario WHERE cedula = ?',
      [cedula]
    )

    if (cedulas.length > 0) {
      res.redirect('/admin/?error=La cedula ya existe.');
    } else {
      if (users.length > 0) {
        res.redirect('/admin/?error=El usuario ya existe.');
      } else {
        const hashedPassword = await bcrypt.hash(contrasena, 10);
        await pool.execute(
          'INSERT INTO usuario (id_rol, nombre, apellido, cedula, username, contraseña) VALUES (?, ?, ?, ?, ?, ?)',
          [id_rol, nombre, apellido, cedula, username, hashedPassword]
        );
        res.redirect('/admin/?success=Usuario registrado con exito.');
      }
    }


  } catch (error) {
    console.error('Error en registro:', error);
    res.redirect('/admin/?error=Error en el sistema.');
  }
});


module.exports = router;

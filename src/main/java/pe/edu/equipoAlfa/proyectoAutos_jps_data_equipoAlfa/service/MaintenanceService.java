package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service;

import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;

import java.util.List;

public interface MaintenanceService {

    //para clientes

    List<ClientesListarDto> getAllClients();
    ClientesDetallesDto getClienteDetalleById(Integer id);
    void registrarCliente(ClientesRegistrarDto clientesRegistrarDto);

    // Para Editar / Atualizar
    ClientesEditarDto getClientesEditarById(int id);
    public void postClientesEditarById(int id, ClientesEditarDto clientesEditarDto);

    //para Borrar
    public void postClientesBorrarById(int id, ClientesBorrarDto clientesBorrarDto);

    //borrar prueba
    public boolean deleteClientesById(int id) throws Exception;

    //---------------------------------------------para vehiculos----------------------------------------------//

    // para listar vehiculos

    List<VehiculosListarDto> getAllVehiculos();

    // para registrar
    void registrarVehiculo(VehiculosRegistrarDto vehiculosRegistrarDto);

    // para listar
    List<CatVehiculos> getAllCategorias();

    // para eliminar
    void eliminarVehiculo(Integer idVehi);

    // para actualizar ( recoge id de vehiculo )
    VehiculosEditarDto getVehiculoById(Integer idVehi);

    // para actualizar ( settea la nueva actualización )
    void actualizarVehiculo(VehiculosEditarDto vehiculosEditarDto);

    //para categoria

    // detalles categoria para vehiculo
    CatVehiculoDetalles getCategoriaDetalleByVehiculoId(Integer id);




}

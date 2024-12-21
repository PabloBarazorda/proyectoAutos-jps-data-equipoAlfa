package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service;

import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CarritoComprasListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CarritoComprasRegistrarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.VehiculosListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Clientes;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Vehiculos;

import java.math.BigDecimal;
import java.util.List;

public interface MaintenanceCarritoService {


    //para compra
    public Boolean realizarCompraCarrito(CarritoComprasRegistrarDto carritoComprasRegistrarDto);

    // para listar
    List<Vehiculos> getAllVehiculos();

    // para listar
    List<Clientes> getAllClientes();

    public List<CarritoComprasListarDto> getAllCarritoCompras();

    public boolean deleteCarritoCompraById(int id) throws Exception;
}
